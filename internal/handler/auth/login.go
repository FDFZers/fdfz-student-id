package auth

import (
	"errors"
	"fdfz-student-id/internal/cfg"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/service/auth"
	"fdfz-student-id/internal/service/captcha"
	"fdfz-student-id/internal/service/perm"
	"fdfz-student-id/internal/service/user"
	crypto2 "fdfz-student-id/internal/util/crypto"
	"fdfz-student-id/internal/util/validation"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func cookieDomain() string {
	if cfg.IsProd {
		return ".fdfz.top"
	}
	return ".ffhub.localhost"
}

func setTokenCookies(c *gin.Context, accessToken, sessionToken string, accessMaxAge, sessionMaxAge int) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("access_token", accessToken, accessMaxAge, "/", cookieDomain(), cfg.IsProd, false)
	c.SetCookie("session_token", sessionToken, sessionMaxAge, "/", cookieDomain(), cfg.IsProd, true)
}

func respondBanned(c *gin.Context, ban *model.UserBan, item string) {
	if ban.EndTime.Valid {
		errs.PermissionDeniedError().AppendDetails(
			fmt.Sprintf("用户已封禁：%s（%s）", ban.Reason, ban.EndTime.Time.Format("2006-01-02 15:04:05")),
			item,
		).Respond(c)
	} else {
		errs.PermissionDeniedError().AppendDetails(
			fmt.Sprintf("用户已永久封禁：%s", ban.Reason),
			item,
		).Respond(c)
	}
}

type loginInitRequestReq struct {
	Username      string `json:"username"`
	Password      string `json:"password"`
	IsTemporary   bool   `json:"is_temporary"`
	AltchaPayload string `json:"altcha_payload"`
}

func loginInitHandler(c *gin.Context) {
	var req loginInitRequestReq
	if err := c.ShouldBindJSON(&req); err != nil {
		errs.BadRequestError().AppendDetails("请求解析失败", "登录失败").Respond(c)
		return
	}

	if err := captcha.VerifyPayloadStr(req.AltchaPayload); err != nil {
		err.AppendDetails("登录失败").Respond(c)
		return
	}

	if err := validation.ValidateUsername(req.Username); err != nil {
		err.AppendDetails("登录失败").Respond(c)
		return
	}
	if err := validation.ValidatePassword(req.Password); err != nil {
		err.AppendDetails("登录失败").Respond(c)
		return
	}

	usr, err := user.GetUserByUsername(c.Request.Context(), req.Username)
	if err != nil {
		err.AppendDetails("登录失败").Respond(c)
		return
	} else if usr == nil {
		errs.ForbiddenError().AppendDetails("用户名或密码错误", "密码验证失败", "登录失败").Respond(c)
		return
	}

	if err := auth.ValidateUserPassword(c.Request.Context(), usr.ID, req.Password); err != nil {
		err.AppendDetails("登录失败").Respond(c)
		return
	}

	ban, err := user.GetUserBan(c.Request.Context(), usr.ID)
	if err != nil {
		err.AppendDetails("登录失败").Respond(c)
		return
	}
	if ban != nil {
		respondBanned(c, ban, "登录失败")
		return
	}

	_, isSchoolIP := cfg.C.SchoolIPs[c.ClientIP()]
	session, err := auth.CreateAuthSession(c.Request.Context(), auth.AuthSessionTypeLogin, isSchoolIP, usr.ID, req.IsTemporary)
	if err != nil {
		err.AppendDetails("登录失败").Respond(c)
		return
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
	})
}

type loginFinalizeRequestReq struct {
	SessionID uuid.UUID `json:"session_id"`
}

func loginFinalizeHandler(c *gin.Context) {
	var req loginFinalizeRequestReq
	if err := c.ShouldBindJSON(&req); err != nil {
		errs.BadRequestError().AppendDetails("请求解析失败", "登录失败").Respond(c)
		return
	}

	authSession, err := auth.GetAuthSessionByID(c.Request.Context(), req.SessionID)
	if err != nil {
		err.AppendDetails("登录失败").Respond(c)
		return
	} else if authSession == nil {
		errs.NotFoundError().AppendDetails("鉴权会话不存在", "登录失败").Respond(c)
		return
	}

	if authSession.Type != auth.AuthSessionTypeLogin {
		errs.BadRequestError().AppendDetails("鉴权会话类型错误", "登录失败").Respond(c)
		return
	}
	if !authSession.Passed2FA {
		errs.IllegalStateError().AppendDetails("二次验证未通过", "登录失败").Respond(c)
		return
	}

	ban, err := user.GetUserBan(c.Request.Context(), authSession.UserID)
	if err != nil {
		err.AppendDetails("登录失败").Respond(c)
		return
	}
	if ban != nil {
		respondBanned(c, ban, "登录失败")
		return
	}

	sessionToken, error := crypto2.GenerateCode(128, crypto2.TokenCharset)
	if error != nil {
		errs.CreateAndLogInternalError(error, "Failed to generate session token").AppendDetails("令牌生成失败", "登录失败").Respond(c)
		return
	}
	sessionTokenHash := crypto2.HashSHA512(sessionToken)

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
		err.AppendDetails("登录失败").Respond(c)
		return
	}

	rollback := func(err *errs.Error) *errs.Error {
		if deleteErr := auth.DeleteSession(c.Request.Context(), session.UUID); deleteErr != nil {
			return err.AppendDetails("登录失败且回退失败，请联系管理员").AppendDetails(deleteErr.Info.Details...)
		}
		return err.AppendDetails("登录失败")
	}

	perms, err := user.GetUserPerms(c.Request.Context(), authSession.UserID)
	if err != nil {
		rollback(err).Respond(c)
		return
	}

	accessToken, error := crypto2.GenerateJWT(session.UUID, &model.TokenClaims{
		UserID:      authSession.UserID,
		TokenType:   model.TokenTypeUser,
		Permissions: perm.MatchAll(perms),
		IsTemporary: authSession.IsTemporary,
	}, cfg.C.AccessTokenTTL)
	if error != nil {
		rollback(errs.CreateAndLogInternalError(error, "Failed to generate access token").AppendDetails("令牌生成失败")).Respond(c)
		return
	}

	exp, err := auth.UpdateSessionClient(c, session.UUID, sessionTokenHash)
	if err != nil {
		rollback(err).Respond(c)
		return
	}

	if err := auth.DeleteAuthSession(c.Request.Context(), authSession); err != nil {
		slog.Warn("Failed to delete auth session after login", "error", err.Info.Error, "session_id", authSession.ID)
	}

	setTokenCookies(c, accessToken, sessionToken, int(cfg.C.AccessTokenTTL.Seconds()), int(exp.Sub(time.Now()).Seconds()))

	c.JSON(http.StatusOK, gin.H{})
}

func refreshTokenHandler(c *gin.Context) {
	sessionToken, error := c.Cookie("session_token")
	if errors.Is(error, http.ErrNoCookie) {
		errs.NotFoundError().AppendDetails("会话令牌不存在").Respond(c)
		return
	} else if error != nil {
		errs.CreateAndLogInternalError(error, "Failed to get session token cookie").AppendDetails("会话令牌获取失败", "令牌刷新失败").Respond(c)
		return
	}

	hash := crypto2.HashSHA512(sessionToken)

	session, err := auth.GetSessionByTokenHash(c.Request.Context(), hash)
	if err != nil {
		errs.CreateAndLogInternalError(err, "Failed to get session by token hash").AppendDetails("会话获取失败", "令牌刷新失败").Respond(c)
		return
	} else if session == nil {
		errs.NotFoundError().AppendDetails("会话不存在或已过期", "令牌刷新失败").Respond(c)
		return
	}

	usr, err := user.GetUserByID(c.Request.Context(), session.UserID)
	if err != nil {
		err.AppendDetails("令牌刷新失败").Respond(c)
		return
	} else if usr == nil {
		errs.NotFoundError().AppendDetails("用户不存在", "令牌刷新失败").Respond(c)
		return
	}

	ban, err := user.GetUserBan(c.Request.Context(), usr.ID)
	if err != nil {
		err.AppendDetails("令牌刷新失败").Respond(c)
		return
	}
	if ban != nil {
		respondBanned(c, ban, "令牌刷新失败")
		return
	}

	sessionToken, error = crypto2.GenerateCode(128, crypto2.TokenCharset)
	if error != nil {
		errs.CreateAndLogInternalError(error, "Failed to generate session token").AppendDetails("令牌生成失败", "登录失败").Respond(c)
		return
	}
	sessionTokenHash := crypto2.HashSHA512(sessionToken)

	perms, err := user.GetUserPerms(c.Request.Context(), session.UserID)
	if err != nil {
		err.AppendDetails("令牌刷新失败").Respond(c)
		return
	}

	accessToken, error := crypto2.GenerateJWT(session.UUID, &model.TokenClaims{
		UserID:      session.UserID,
		TokenType:   model.TokenTypeUser,
		Permissions: perm.MatchAll(perms),
		IsTemporary: session.IsTemporary,
	}, cfg.C.AccessTokenTTL)
	if error != nil {
		errs.CreateAndLogInternalError(error, "Failed to generate access token").AppendDetails("令牌生成失败", "令牌刷新失败").Respond(c)
		return
	}

	exp, err := auth.UpdateSessionClient(c, session.UUID, sessionTokenHash)
	if err != nil {
		err.AppendDetails("令牌刷新失败").Respond(c)
		return
	}

	setTokenCookies(c, accessToken, sessionToken, int(cfg.C.AccessTokenTTL.Seconds()), int(exp.Sub(time.Now()).Seconds()))

	c.JSON(http.StatusOK, gin.H{})
}

func logoutHandler(c *gin.Context) {
	claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)

	sessionID, err := uuid.Parse(claims.ID)
	if err != nil {
		errs.InvalidTokenError().AppendDetails("无效的会话", "登出失败").Respond(c)
		return
	}

	if err := auth.RevokeSession(c.Request.Context(), sessionID); err != nil {
		err.AppendDetails("登出失败").Respond(c)
		return
	}

	setTokenCookies(c, "", "", 0, 0)
	setStepupCookie(c, "", -1)
	c.JSON(http.StatusOK, gin.H{})
}
