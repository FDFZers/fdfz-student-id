package auth

import (
	"errors"
	"fdfz-student-id/internal/cfg"
	"fdfz-student-id/internal/crypto"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/perm"
	"fdfz-student-id/internal/service/auth"
	"fdfz-student-id/internal/service/captcha"
	"fdfz-student-id/internal/service/user"
	"fdfz-student-id/internal/validation"
	"fmt"
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
	}

	ban, err := user.GetUserBan(c.Request.Context(), usr.ID)
	if err != nil {
		err.AppendDetails("登录失败").Respond(c)
		return
	}
	if ban != nil && ban.Enabled {
		if ban.EndTime.Valid {
			errs.PermissionDeniedError().AppendDetails(
				fmt.Sprintf("用户已封禁：%s（%s）", ban.Reason, ban.EndTime.Time.Format("2006-01-02 15:04:05")),
				"登录失败",
			).Respond(c)
		} else {
			errs.PermissionDeniedError().AppendDetails(
				fmt.Sprintf("用户已永久封禁：%s", ban.Reason),
				"登录失败",
			).Respond(c)
		}
		return
	}

	if err := auth.ValidateUserPassword(c.Request.Context(), usr.ID, req.Password); err != nil {
		err.AppendDetails("登录失败").Respond(c)
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

	sessionToken, cErr := crypto.GenerateCode(128, crypto.TokenCharset)
	if cErr != nil {
		errs.CreateAndLogInternalError(cErr, "Failed to generate session token").AppendDetails("令牌生成失败", "登录失败").Respond(c)
		return
	}
	sessionTokenHash, cErr := crypto.HashArgon2ID(sessionToken)
	if cErr != nil {
		errs.CreateAndLogInternalError(cErr, "Failed to hash session token").AppendDetails("令牌生成失败", "登录失败").Respond(c)
		return
	}

	var dur time.Duration
	if authSession.IsTemporary {
		dur = cfg.C.TempSessionTokenTTL
	} else {
		dur = cfg.C.PermSessionTokenTTL
	}

	session := &model.UserSession{
		UserID:      authSession.UserID,
		IsTemporary: authSession.IsTemporary,
		ExpiresAt:   time.Now().Add(dur),
	}
	if err := auth.CreateSession(c.Request.Context(), session); err != nil {
		err.AppendDetails("登录失败").Respond(c)
		return
	}

	rollback := func(error *errs.Error) *errs.Error {
		if err := auth.DeleteSession(c.Request.Context(), session.UUID); err != nil {
			return error.AppendDetails("登录失败且回退失败，请联系管理员").AppendDetails(err.Info.Details...)
		}
		return error.AppendDetails("登录失败")
	}

	perms, err := user.GetUserPerms(c.Request.Context(), authSession.UserID)
	if err != nil {
		rollback(err).Respond(c)
		return
	}

	accessToken, cErr := crypto.GenerateJWT(session.UUID, &model.TokenClaims{
		UserID:      authSession.UserID,
		TokenType:   model.TokenTypeUser,
		Permissions: perm.MatchAll(perms),
		IsTemporary: authSession.IsTemporary,
	})
	if cErr != nil {
		rollback(errs.CreateAndLogInternalError(cErr, "Failed to generate access token").AppendDetails("令牌生成失败")).Respond(c)
		return
	}

	exp, err := auth.UpdateSessionClient(c, session.UUID, sessionTokenHash)
	if err != nil {
		rollback(err).Respond(c)
		return
	}

	c.SetCookie("access_token", accessToken, int(cfg.C.AccessTokenTTL.Seconds()), "/", "fdfz.top", false, false)
	c.SetCookie("session_token", sessionToken, int(exp.Sub(time.Now()).Seconds()), "/", "fdfz.top", true, true)

	c.JSON(http.StatusOK, gin.H{})
}

func refreshTokenHandler(c *gin.Context) {
	sessionToken, err := c.Cookie("session_token")
	if errors.Is(err, http.ErrNoCookie) {
		errs.NotFoundError().AppendDetails("会话令牌不存在").Respond(c)
		return
	} else if err != nil {
		errs.CreateAndLogInternalError(err, "Failed to get session token cookie").AppendDetails("会话令牌获取失败", "令牌刷新失败").Respond(c)
		return
	}

	hash, err := crypto.HashArgon2ID(sessionToken)
	if err != nil {
		errs.CreateAndLogInternalError(err, "Failed to hash session token").AppendDetails("令牌哈希失败", "令牌刷新失败").Respond(c)
		return
	}

	session, sErr := auth.GetSessionByTokenHash(c.Request.Context(), hash)
	if sErr != nil {
		errs.CreateAndLogInternalError(sErr, "Failed to get session by token hash").AppendDetails("会话获取失败", "令牌刷新失败").Respond(c)
		return
	} else if session == nil {
		errs.NotFoundError().AppendDetails("会话不存在", "令牌刷新失败").Respond(c)
		return
	}

	usr, uErr := user.GetUserByID(c.Request.Context(), session.UserID)
	if uErr != nil {
		uErr.AppendDetails("令牌刷新失败").Respond(c)
		return
	}

	ban, uErr := user.GetUserBan(c.Request.Context(), usr.ID)
	if uErr != nil {
		uErr.AppendDetails("令牌刷新失败").Respond(c)
		return
	}
	if ban != nil && ban.Enabled {
		if ban.EndTime.Valid {
			errs.PermissionDeniedError().AppendDetails(
				fmt.Sprintf("用户已封禁：%s（%s）", ban.Reason, ban.EndTime.Time.Format("2006-01-02 15:04:05")),
				"令牌刷新失败",
			).Respond(c)
		} else {
			errs.PermissionDeniedError().AppendDetails(
				fmt.Sprintf("用户已永久封禁：%s", ban.Reason),
				"令牌刷新失败",
			).Respond(c)
		}
		return
	}

	sessionToken, cErr := crypto.GenerateCode(128, crypto.TokenCharset)
	if cErr != nil {
		errs.CreateAndLogInternalError(cErr, "Failed to generate session token").AppendDetails("令牌生成失败", "登录失败").Respond(c)
		return
	}
	sessionTokenHash, cErr := crypto.HashArgon2ID(sessionToken)
	if cErr != nil {
		errs.CreateAndLogInternalError(cErr, "Failed to hash session token").AppendDetails("令牌生成失败", "登录失败").Respond(c)
		return
	}

	perms, uErr := user.GetUserPerms(c.Request.Context(), session.UserID)
	if uErr != nil {
		uErr.AppendDetails("令牌刷新失败").Respond(c)
		return
	}

	accessToken, cErr := crypto.GenerateJWT(session.UUID, &model.TokenClaims{
		UserID:      session.UserID,
		TokenType:   model.TokenTypeUser,
		Permissions: perm.MatchAll(perms),
		IsTemporary: session.IsTemporary,
	})
	if cErr != nil {
		errs.CreateAndLogInternalError(cErr, "Failed to generate access token").AppendDetails("令牌生成失败", "令牌刷新失败").Respond(c)
		return
	}

	exp, aErr := auth.UpdateSessionClient(c, session.UUID, sessionTokenHash)
	if aErr != nil {
		aErr.AppendDetails("令牌刷新失败").Respond(c)
		return
	}

	c.SetCookie("access_token", accessToken, int(cfg.C.AccessTokenTTL.Seconds()), "/", "fdfz.top", false, false)
	c.SetCookie("session_token", sessionToken, int(exp.Sub(time.Now()).Seconds()), "/", "fdfz.top", true, true)

	c.JSON(http.StatusOK, gin.H{})
}
