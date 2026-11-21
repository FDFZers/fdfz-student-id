package auth

import (
	"context"
	"errors"
	"fdfz-student-id/internal/cfg"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	authsvc "fdfz-student-id/internal/service/auth"
	captchasvc "fdfz-student-id/internal/service/captcha"
	notifysvc "fdfz-student-id/internal/service/notify"
	permsvc "fdfz-student-id/internal/service/perm"
	usersvc "fdfz-student-id/internal/service/user"
	userpermsvc "fdfz-student-id/internal/service/userperm"
	"fdfz-student-id/internal/util/crypto"
	"fdfz-student-id/internal/util/handling"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// loginInitRequestReq 是登录初始化的请求体。
type loginInitRequestReq struct {
	Username      string `json:"username"`       // 用户名
	Password      string `json:"password"`       // 密码
	IsTemporary   bool   `json:"is_temporary"`   // 是否申请临时会话
	AltchaPayload string `json:"altcha_payload"` // Altcha 人机验证载荷
}

// loginInitHandler 校验用户名密码、封禁状态与 Altcha，创建登录用鉴权会话并返回可用的二次验证方式。
// 注意：账号被封禁时返回 banned=true 的封禁信息，不创建鉴权会话；
// 不需要二次验证（校园 IP、用户关闭登录二次验证或未绑定任何方式）时直接返回 passed=true，由 finalize 建会话；
// 用户不存在时也执行一次密码哈希，避免通过响应耗时枚举账号。
func loginInitHandler(c *gin.Context) *errs.Error {
	var req loginInitRequestReq
	if err := handling.BindJSON(c, &req); err != nil {
		return err
	}

	if err := captchasvc.VerifyPayloadStr(c.Request.Context(), req.AltchaPayload); err != nil {
		return err
	}

	if err := handling.ValidateUsername(req.Username); err != nil {
		return err
	}
	if err := handling.ValidatePassword(req.Password); err != nil {
		return err
	}

	// Argon2 校验前先做账号/IP 失败次数限流，防止暴力破解。
	if err := authsvc.CheckLoginRateLimit(c.Request.Context(), req.Username, c.ClientIP()); err != nil {
		return err
	}

	usr, err := usersvc.GetUserByUsername(c.Request.Context(), req.Username)
	if err != nil {
		return err
	} else if usr == nil {
		crypto.BurnPasswordVerifyCost()
		authsvc.RecordLoginFailure(c.Request.Context(), req.Username, c.ClientIP())
		return errs.ForbiddenError().AppendDetails("用户名或密码错误")
	}

	if err := authsvc.ValidateUserPassword(c.Request.Context(), usr.ID, req.Password); err != nil {
		if err.HTTPCode == http.StatusForbidden {
			authsvc.RecordLoginFailure(c.Request.Context(), req.Username, c.ClientIP())
		}
		return err
	}
	authsvc.ResetLoginFailures(c.Request.Context(), req.Username)

	ban, err := usersvc.GetUserBan(c.Request.Context(), usr.ID)
	if err != nil {
		return err
	}
	if ban != nil {
		// 凭据已验证，直接返回封禁信息供前端展示封禁页，不创建鉴权会话
		c.JSON(http.StatusOK, handling.BanJSON(ban))
		return nil
	}

	// 校园 IP 内登录免二次验证；其余场景按已绑定的方式启用验证，用户主动关闭登录二次验证时同样跳过。
	_, isSchoolIP := cfg.C.SchoolIPs.Lookup(c.ClientIP())
	session, err := authsvc.CreateAuthSession(c.Request.Context(), authsvc.AuthSessionTypeLogin, isSchoolIP, usr.ID, req.IsTemporary, usr.TwoFactorEnabled)
	if err != nil {
		return err
	}

	methods := make([]string, 0, 3)
	if session.TOTPSecret.Valid {
		methods = append(methods, "totp")
	}
	if session.Email.Valid {
		methods = append(methods, "email")
	}
	if session.QQ.Valid {
		methods = append(methods, "qq")
	}

	c.JSON(http.StatusOK, gin.H{
		"banned":     false,
		"session_id": session.ID,
		"2fa":        methods,
		"passed":     session.Passed2FA,
	})
	return nil
}

// loginFinalizeRequestReq 是登录完成的请求体。
type loginFinalizeRequestReq struct {
	SessionID uuid.UUID `json:"session_id"` // 登录初始化返回的鉴权会话 ID
	Password  string    `json:"password"`
}

// loginFinalizeHandler 完成登录：校验鉴权会话状态，创建用户会话并签发访问令牌、写入 Cookie。
// 注意：会话必须已通过二次验证；登录成功会取消冷静期内的账号注销，若注销已到期则先执行注销再拒绝登录。
func loginFinalizeHandler(c *gin.Context) *errs.Error {
	var req loginFinalizeRequestReq
	if err := handling.BindJSON(c, &req); err != nil {
		return err
	}

	// 校验鉴权会话状态
	authSession, err := authsvc.GetAuthSessionByID(c.Request.Context(), req.SessionID)
	if err != nil {
		return err
	} else if authSession == nil {
		return errs.NotFoundError().AppendDetails("鉴权会话不存在")
	}

	if authSession.Type != authsvc.AuthSessionTypeLogin {
		return errs.BadRequestError().AppendDetails("鉴权会话类型错误")
	}
	if !authSession.Passed2FA {
		return errs.IllegalStateError().AppendDetails("二次验证未通过")
	}

	// 二次校验封禁状态，防止用户在校验密码后被封禁
	ban, err := usersvc.GetUserBan(c.Request.Context(), authSession.UserID)
	if err != nil {
		return err
	}
	if ban != nil {
		return handling.BannedError(ban)
	}

	// 冷静期内重新登录取消账号注销
	cancelled, err := usersvc.CancelPendingAccountDeletion(c.Request.Context(), authSession.UserID)
	if err != nil {
		return err
	} else if cancelled {
		slog.Info("Cancelled scheduled account deletion on login", "user_id", authSession.UserID)
	}
	// 注销可能已到期：先执行注销，再按凭据错误返回，避免泄露账号已注销
	finalized, err := usersvc.FinalizeOverdueAccountDeletion(c.Request.Context(), authSession.UserID)
	if err != nil {
		return err
	} else if finalized {
		slog.Info("Finalized overdue account deletion on login", "user_id", authSession.UserID)
		return errs.ForbiddenError().AppendDetails("用户名或密码错误")
	}

	usr, err := usersvc.GetUserByID(c.Request.Context(), authSession.UserID)
	if err != nil {
		return err
	} else if usr == nil {
		return errs.ForbiddenError().AppendDetails("用户名或密码错误")
	}

	// 管理员重置密码后必须先设置新密码才能完成登录
	if usr.PasswordResetRequired {
		if req.Password == "" {
			// 延长鉴权会话，给用户留出设置新密码的时间；未提供密码时前端据此展示重设表单
			if err := authsvc.UpdateAuthSession(c.Request.Context(), authSession, true); err != nil {
				return err
			}
			return errs.PasswordResetRequiredError().AppendDetails("请设置新密码后继续登录").Seal()
		}
		if err := resetPasswordAtLogin(c.Request.Context(), usr.ID, req.Password); err != nil {
			return err
		}
	}
	// 不需要重设密码时忽略 password 字段，保持接口可重试等幂等语义

	// 创建用户会话并生成会话令牌
	sessionToken, e := crypto.GenerateCode(128, crypto.TokenCharset)
	if e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to generate session token").AppendDetails("令牌生成失败")
	}
	sessionTokenHash := crypto.HashSHA512(sessionToken)

	// 临时会话与普通会话使用不同的会话过期时间
	var dur time.Duration
	if authSession.IsTemporary {
		dur = cfg.C.TempSessionTokenTTL
	} else {
		dur = cfg.C.PermSessionTokenTTL
	}

	session := &model.UserSession{
		UserID:           authSession.UserID,
		SessionTokenHash: sessionTokenHash,
		IsTemporary:      authSession.IsTemporary,
		ExpiresAt:        time.Now().Add(dur),
	}
	if err := authsvc.CreateSession(c.Request.Context(), session); err != nil {
		return err
	}

	// rollback 在后续步骤失败时删除刚创建的会话，避免留下无法使用的会话记录
	rollback := func(cause *errs.Error) *errs.Error {
		if err := authsvc.DeleteSession(c.Request.Context(), session.UUID); err != nil {
			return cause.AppendDetails("登录失败且回退失败，请联系管理员").AppendDetails(err.Info.Details...).Seal()
		}
		return cause
	}

	// 解析权限并签发访问令牌：令牌内只写权限 ID，具体权限串由 /auth/claims 提供。
	perms, err := userpermsvc.ListUserEffectivePermissions(c.Request.Context(), authSession.UserID)
	if err != nil {
		return rollback(err)
	}

	accessToken, e := crypto.GenerateJWT(session.UUID, &model.TokenClaims{
		UserID:      authSession.UserID,
		TokenType:   model.TokenTypeUser,
		Permissions: permsvc.ToIDs(perms),
		IsTemporary: authSession.IsTemporary,
	}, cfg.C.AccessTokenTTL)
	if e != nil {
		return rollback(errs.CreateAndLogInternalError(e, "Failed to generate access token").AppendDetails("令牌生成失败"))
	}

	// 刷新会话客户端信息并写入 Cookie
	exp, err := authsvc.UpdateSessionClient(c, session.UUID, sessionTokenHash)
	if err != nil {
		return rollback(err)
	}

	// 登录用鉴权会话已完成使命，删除失败只记录日志，不影响登录结果
	if err := authsvc.DeleteAuthSession(c.Request.Context(), authSession); err != nil {
		slog.Warn("Failed to delete login auth session", "error", err.Info.Error, "session_id", authSession.ID)
	}

	handling.SetTokenCookies(c, accessToken, sessionToken, int(cfg.C.AccessTokenTTL.Seconds()), int(exp.Sub(time.Now()).Seconds()))

	handling.RespondOK(c)
	return nil
}

// resetPasswordAtLogin 在登录流程中设置新密码并清除管理员重置标记。
// 注意：新密码须满足复杂度要求且不能与当前密码相同。
func resetPasswordAtLogin(ctx context.Context, userID int64, newPassword string) *errs.Error {
	if err := handling.ValidatePassword(newPassword); err != nil {
		return err
	}

	current, err := usersvc.GetUserPassword(ctx, userID)
	if err != nil {
		return err
	} else if current == nil {
		return errs.NotFoundError().AppendDetails("密码不存在")
	}
	if ok, e := crypto.VerifyArgon2ID(newPassword, current.Password); e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to verify user password").AppendDetails("密码校验失败")
	} else if ok {
		return errs.BadRequestError().AppendDetails("新密码不能与原密码相同")
	}

	pwdHash, e := crypto.HashArgon2ID(newPassword)
	if e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to hash new password").AppendDetails("密码哈希失败")
	}
	if err := usersvc.SetUserPasswordAndClearResetRequired(ctx, userID, pwdHash); err != nil {
		return err
	}

	notifysvc.ToUser(ctx, userID, notifysvc.NewMessage(
		"密码已重设",
		"你的账号密码已在登录时重设",
		"你好！你的复旦附中学生 ID 账号密码已于北京时间 "+notifysvc.BeijingTime()+" 在登录时重设。",
		"如非本人操作，请立即联系管理员。",
	))
	return nil
}

// refreshTokenHandler 用 session_token Cookie 换发新的访问令牌，同时轮换会话令牌。
// 注意：临时会话刷新不会延长会话过期时间；会话被撤销或过期后需要重新登录。
func refreshTokenHandler(c *gin.Context) *errs.Error {
	sessionToken, e := c.Cookie("session_token")
	if errors.Is(e, http.ErrNoCookie) {
		return errs.InvalidTokenError().AppendDetails("未提供会话令牌")
	} else if e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to get session token cookie").AppendDetails("会话令牌获取失败")
	}

	hash := crypto.HashSHA512(sessionToken)

	session, err := authsvc.GetSessionByTokenHash(c.Request.Context(), hash)
	if err != nil {
		return err.AppendDetails("会话获取失败")
	}
	if session == nil {
		return errs.InvalidTokenError().AppendDetails("会话不存在或已过期")
	}

	// 校验用户仍然存在且未被封禁
	usr, err := usersvc.GetUserByID(c.Request.Context(), session.UserID)
	if err != nil {
		return err
	} else if usr == nil {
		return errs.NotFoundError().AppendDetails("用户不存在")
	}

	ban, err := usersvc.GetUserBan(c.Request.Context(), usr.ID)
	if err != nil {
		return err
	}
	if ban != nil {
		return handling.BannedError(ban)
	}

	// 轮换会话令牌并重新签发访问令牌
	sessionToken, e = crypto.GenerateCode(128, crypto.TokenCharset)
	if e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to generate session token").AppendDetails("令牌生成失败")
	}
	sessionTokenHash := crypto.HashSHA512(sessionToken)

	perms, err := userpermsvc.ListUserEffectivePermissions(c.Request.Context(), session.UserID)
	if err != nil {
		return err
	}

	accessToken, e := crypto.GenerateJWT(session.UUID, &model.TokenClaims{
		UserID:      session.UserID,
		TokenType:   model.TokenTypeUser,
		Permissions: permsvc.ToIDs(perms),
		IsTemporary: session.IsTemporary,
	}, cfg.C.AccessTokenTTL)
	if e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to generate access token").AppendDetails("令牌生成失败")
	}

	// 用旧令牌哈希做条件轮换，同一 session_token 并发刷新只有一个请求成功。
	exp, err := authsvc.RotateSessionClient(c, session.UUID, hash, sessionTokenHash)
	if err != nil {
		return err
	}

	handling.SetTokenCookies(c, accessToken, sessionToken, int(cfg.C.AccessTokenTTL.Seconds()), int(exp.Sub(time.Now()).Seconds()))

	handling.RespondOK(c)
	return nil
}

// logoutHandler 撤销当前访问令牌对应的用户会话，并清除会话相关 Cookie。
// 注意：访问令牌本身无状态，撤销后仍可能在剩余有效期内（默认 10 分钟）被接受。
func logoutHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)

	sessionID, e := uuid.Parse(claims.ID)
	if e != nil {
		return errs.InvalidTokenError().AppendDetails("会话 ID 格式错误")
	}

	if err := authsvc.RevokeSession(c.Request.Context(), sessionID); err != nil {
		return err
	}

	handling.ClearSessionCookies(c)
	handling.RespondOK(c)
	return nil
}
