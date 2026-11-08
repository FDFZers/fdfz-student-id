package auth

import (
	"errors"
	"fdfz-student-id/internal/cfg"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/service/app"
	"fdfz-student-id/internal/service/auth"
	"fdfz-student-id/internal/service/captcha"
	"fdfz-student-id/internal/service/perm"
	"fdfz-student-id/internal/service/user"
	"fdfz-student-id/internal/service/userperm"
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
// 注意：不需要二次验证（校园 IP 或未绑定任何方式）时直接返回 passed=true，由 finalize 建会话；
// 用户不存在时也执行一次密码哈希，避免通过响应耗时枚举账号。
func loginInitHandler(c *gin.Context) *errs.Error {
	var req loginInitRequestReq
	if e := c.ShouldBindJSON(&req); e != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}

	if err := captcha.VerifyPayloadStr(c.Request.Context(), req.AltchaPayload); err != nil {
		return err
	}

	if err := handling.ValidateUsername(req.Username); err != nil {
		return err
	}
	if err := handling.ValidatePassword(req.Password); err != nil {
		return err
	}

	usr, err := user.GetUserByUsername(c.Request.Context(), req.Username)
	if err != nil {
		return err
	} else if usr == nil {
		crypto.BurnPasswordVerifyCost()
		return errs.ForbiddenError().AppendDetails("用户名或密码错误")
	}

	if err := auth.ValidateUserPassword(c.Request.Context(), usr.ID, req.Password); err != nil {
		return err
	}

	ban, err := user.GetUserBan(c.Request.Context(), usr.ID)
	if err != nil {
		return err
	}
	if ban != nil {
		return handling.BannedError(ban)
	}

	// 校园 IP 内登录免二次验证，其余场景按已绑定的方式启用验证。
	_, isSchoolIP := cfg.C.SchoolIPs[c.ClientIP()]
	session, err := auth.CreateAuthSession(c.Request.Context(), auth.AuthSessionTypeLogin, isSchoolIP, usr.ID, req.IsTemporary)
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
		"session_id": session.ID,
		"2fa":        methods,
		"passed":     session.Passed2FA,
	})
	return nil
}

// loginFinalizeRequestReq 是登录完成的请求体。
type loginFinalizeRequestReq struct {
	SessionID uuid.UUID `json:"session_id"` // 登录初始化返回的鉴权会话 ID
}

// loginFinalizeHandler 完成登录：校验鉴权会话状态，创建用户会话并签发访问令牌、写入 Cookie。
// 注意：会话必须已通过二次验证；登录成功会取消冷静期内的账号注销，若注销已到期则先执行注销再拒绝登录。
func loginFinalizeHandler(c *gin.Context) *errs.Error {
	var req loginFinalizeRequestReq
	if e := c.ShouldBindJSON(&req); e != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}

	// 校验鉴权会话状态
	authSession, err := auth.GetAuthSessionByID(c.Request.Context(), req.SessionID)
	if err != nil {
		return err
	} else if authSession == nil {
		return errs.NotFoundError().AppendDetails("鉴权会话不存在")
	}

	if authSession.Type != auth.AuthSessionTypeLogin {
		return errs.BadRequestError().AppendDetails("鉴权会话类型错误")
	}
	if !authSession.Passed2FA {
		return errs.IllegalStateError().AppendDetails("二次验证未通过")
	}

	// 二次校验封禁状态，防止用户在校验密码后被封禁
	ban, err := user.GetUserBan(c.Request.Context(), authSession.UserID)
	if err != nil {
		return err
	}
	if ban != nil {
		return handling.BannedError(ban)
	}

	// 冷静期内重新登录取消账号注销
	cancelled, err := user.CancelPendingAccountDeletion(c.Request.Context(), authSession.UserID)
	if err != nil {
		return err
	} else if cancelled {
		slog.Info("Cancelled scheduled account deletion on login", "user_id", authSession.UserID)
	}
	// 注销可能已到期：先执行注销，再按凭据错误返回，避免泄露账号已注销
	finalized, err := user.FinalizeOverdueAccountDeletion(c.Request.Context(), authSession.UserID)
	if err != nil {
		return err
	} else if finalized {
		slog.Info("Finalized overdue account deletion on login", "user_id", authSession.UserID)
		return errs.ForbiddenError().AppendDetails("用户名或密码错误")
	}

	// 用户可能在初始化与完成登录之间被删除：按凭据错误返回，避免为已删除账号创建会话
	if usr, err := user.GetUserByID(c.Request.Context(), authSession.UserID); err != nil {
		return err
	} else if usr == nil {
		return errs.ForbiddenError().AppendDetails("用户名或密码错误")
	}

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
	if err := auth.CreateSession(c.Request.Context(), session); err != nil {
		return err
	}

	// rollback 在后续步骤失败时删除刚创建的会话，避免留下无法使用的会话记录
	rollback := func(err *errs.Error) *errs.Error {
		if deleteErr := auth.DeleteSession(c.Request.Context(), session.UUID); deleteErr != nil {
			return err.AppendDetails("登录失败且回退失败，请联系管理员").AppendDetails(deleteErr.Info.Details...).Seal()
		}
		return err
	}

	// 解析权限与所属应用，签发访问令牌
	perms, err := userperm.ListUserEffectivePermissions(c.Request.Context(), authSession.UserID)
	if err != nil {
		return rollback(err)
	}
	ownedApps, err := app.ListOwnedAppIDs(c.Request.Context(), authSession.UserID)
	if err != nil {
		return rollback(err)
	}

	accessToken, e := crypto.GenerateJWT(session.UUID, &model.TokenClaims{
		UserID:      authSession.UserID,
		TokenType:   model.TokenTypeUser,
		Permissions: perm.ResolvePatterns(perms),
		OwnedApps:   ownedApps,
		IsTemporary: authSession.IsTemporary,
	}, cfg.C.AccessTokenTTL)
	if e != nil {
		return rollback(errs.CreateAndLogInternalError(e, "Failed to generate access token").AppendDetails("令牌生成失败"))
	}

	// 刷新会话客户端信息并写入 Cookie
	exp, err := auth.UpdateSessionClient(c, session.UUID, sessionTokenHash)
	if err != nil {
		return rollback(err)
	}

	// 登录用鉴权会话已完成使命，删除失败只记录日志，不影响登录结果
	if err := auth.DeleteAuthSession(c.Request.Context(), authSession); err != nil {
		slog.Warn("Failed to delete login auth session", "error", err.Info.Error, "session_id", authSession.ID)
	}

	handling.SetTokenCookies(c, accessToken, sessionToken, int(cfg.C.AccessTokenTTL.Seconds()), int(exp.Sub(time.Now()).Seconds()))

	c.JSON(http.StatusOK, gin.H{})
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

	session, err := auth.GetSessionByTokenHash(c.Request.Context(), hash)
	if err != nil {
		return err.AppendDetails("会话获取失败")
	}
	// 会话不存在/已过期/已撤销时 service 返回 nil，应告知客户端重新登录。
	if session == nil {
		return errs.InvalidTokenError().AppendDetails("会话不存在或已过期")
	}

	// 校验用户仍然存在且未被封禁
	usr, err := user.GetUserByID(c.Request.Context(), session.UserID)
	if err != nil {
		return err
	} else if usr == nil {
		return errs.NotFoundError().AppendDetails("用户不存在")
	}

	ban, err := user.GetUserBan(c.Request.Context(), usr.ID)
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

	perms, err := userperm.ListUserEffectivePermissions(c.Request.Context(), session.UserID)
	if err != nil {
		return err
	}
	ownedApps, err := app.ListOwnedAppIDs(c.Request.Context(), session.UserID)
	if err != nil {
		return err
	}

	accessToken, e := crypto.GenerateJWT(session.UUID, &model.TokenClaims{
		UserID:      session.UserID,
		TokenType:   model.TokenTypeUser,
		Permissions: perm.ResolvePatterns(perms),
		OwnedApps:   ownedApps,
		IsTemporary: session.IsTemporary,
	}, cfg.C.AccessTokenTTL)
	if e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to generate access token").AppendDetails("令牌生成失败")
	}

	// 更新会话客户端信息并重写 Cookie
	exp, err := auth.UpdateSessionClient(c, session.UUID, sessionTokenHash)
	if err != nil {
		return err
	}

	handling.SetTokenCookies(c, accessToken, sessionToken, int(cfg.C.AccessTokenTTL.Seconds()), int(exp.Sub(time.Now()).Seconds()))

	c.JSON(http.StatusOK, gin.H{})
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

	if err := auth.RevokeSession(c.Request.Context(), sessionID); err != nil {
		return err
	}

	handling.ClearSessionCookies(c)
	c.JSON(http.StatusOK, gin.H{})
	return nil
}
