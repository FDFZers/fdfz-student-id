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

type loginInitRequestReq struct {
	Username      string `json:"username"`
	Password      string `json:"password"`
	IsTemporary   bool   `json:"is_temporary"`
	AltchaPayload string `json:"altcha_payload"`
}

func loginInitHandler(c *gin.Context) *errs.Error {
	var req loginInitRequestReq
	if err := c.ShouldBindJSON(&req); err != nil {
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
		return errs.ForbiddenError().AppendDetails("用户名或密码错误", "密码验证失败")
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

type loginFinalizeRequestReq struct {
	SessionID uuid.UUID `json:"session_id"`
}

func loginFinalizeHandler(c *gin.Context) *errs.Error {
	var req loginFinalizeRequestReq
	if err := c.ShouldBindJSON(&req); err != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}

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
	// 可能注销已到期
	finalized, err := user.FinalizeOverdueAccountDeletion(c.Request.Context(), authSession.UserID)
	if err != nil {
		return err
	} else if finalized {
		slog.Info("Finalized overdue account deletion on login", "user_id", authSession.UserID)
		return errs.ForbiddenError().AppendDetails("用户名或密码错误", "密码验证失败").Seal()
	}

	sessionToken, e := crypto.GenerateCode(128, crypto.TokenCharset)
	if e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to generate session token").AppendDetails("令牌生成失败")
	}
	sessionTokenHash := crypto.HashSHA512(sessionToken)

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

	rollback := func(err *errs.Error) *errs.Error {
		if deleteErr := auth.DeleteSession(c.Request.Context(), session.UUID); deleteErr != nil {
			return err.AppendDetails("登录失败且回退失败，请联系管理员").AppendDetails(deleteErr.Info.Details...).Seal()
		}
		return err
	}

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

	exp, err := auth.UpdateSessionClient(c, session.UUID, sessionTokenHash)
	if err != nil {
		return rollback(err)
	}

	if err := auth.DeleteAuthSession(c.Request.Context(), authSession); err != nil {
		slog.Warn("Failed to delete login auth session", "error", err.Info.Error, "session_id", authSession.ID)
	}

	handling.SetTokenCookies(c, accessToken, sessionToken, int(cfg.C.AccessTokenTTL.Seconds()), int(exp.Sub(time.Now()).Seconds()))

	c.JSON(http.StatusOK, gin.H{})
	return nil
}

func refreshTokenHandler(c *gin.Context) *errs.Error {
	sessionToken, e := c.Cookie("session_token")
	if errors.Is(e, http.ErrNoCookie) {
		return errs.NotFoundError().AppendDetails("会话令牌不存在").Seal()
	} else if e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to get session token cookie").AppendDetails("会话令牌获取失败")
	}

	hash := crypto.HashSHA512(sessionToken)

	session, err := auth.GetSessionByTokenHash(c.Request.Context(), hash)
	if err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to get session by token hash").AppendDetails("会话获取失败")
	} else if session == nil {
		return errs.NotFoundError().AppendDetails("会话不存在或已过期")
	}

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

	sessionToken, e = crypto.GenerateCode(128, crypto.TokenCharset)
	if e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to generate session token").AppendDetails("令牌生成失败", "登录失败").Seal()
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

	exp, err := auth.UpdateSessionClient(c, session.UUID, sessionTokenHash)
	if err != nil {
		return err
	}

	handling.SetTokenCookies(c, accessToken, sessionToken, int(cfg.C.AccessTokenTTL.Seconds()), int(exp.Sub(time.Now()).Seconds()))

	c.JSON(http.StatusOK, gin.H{})
	return nil
}

func logoutHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)

	sessionID, err := uuid.Parse(claims.ID)
	if err != nil {
		return errs.InvalidTokenError().AppendDetails("无效的会话")
	}

	if err := auth.RevokeSession(c.Request.Context(), sessionID); err != nil {
		return err
	}

	handling.ClearSessionCookies(c)
	c.JSON(http.StatusOK, gin.H{})
	return nil
}
