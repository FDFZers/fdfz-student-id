package auth

import (
	"fdfz-student-id/internal/cfg"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/service/auth"
	"fdfz-student-id/internal/service/user"
	crypto2 "fdfz-student-id/internal/util/crypto"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func setStepupCookie(c *gin.Context, token string, maxAge int) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("stepup_token", token, maxAge, "/", cookieDomain(), true, true)
}

func stepupInitHandler(c *gin.Context) {
	claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)

	if claims.IsTemporary {
		errs.PermissionDeniedError().AppendDetails("临时会话不支持二次验证", "二次验证初始化失败").Respond(c)
		return
	}

	ban, err := user.GetUserBan(c.Request.Context(), claims.UserID)
	if err != nil {
		err.AppendDetails("二次验证初始化失败").Respond(c)
		return
	}
	if ban != nil {
		respondBanned(c, ban, "二次验证初始化失败")
		return
	}

	session, err := auth.CreateAuthSession(c.Request.Context(), auth.AuthSessionTypeStepup, false, claims.UserID, false)
	if err != nil {
		err.AppendDetails("二次验证初始化失败").Respond(c)
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
		"passed":     session.Passed2FA,
	})
}

type stepupFinalizeReq struct {
	SessionID uuid.UUID `json:"session_id"`
}

func stepupFinalizeHandler(c *gin.Context) {
	var req stepupFinalizeReq
	if err := c.ShouldBindJSON(&req); err != nil {
		errs.BadRequestError().AppendDetails("请求解析失败", "二次验证失败").Respond(c)
		return
	}
	if req.SessionID == uuid.Nil {
		errs.BadRequestError().AppendDetails("无效的鉴权会话 ID", "二次验证失败").Respond(c)
		return
	}

	claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)

	session, err := auth.GetAuthSessionByID(c.Request.Context(), req.SessionID)
	if err != nil {
		err.AppendDetails("二次验证失败").Respond(c)
		return
	} else if session == nil {
		errs.NotFoundError().AppendDetails("鉴权会话不存在", "二次验证失败").Respond(c)
		return
	}

	if session.Type != auth.AuthSessionTypeStepup {
		errs.BadRequestError().AppendDetails("鉴权会话类型错误", "二次验证失败").Respond(c)
		return
	}
	if session.UserID != claims.UserID {
		errs.ForbiddenError().AppendDetails("鉴权会话不属于当前用户", "二次验证失败").Respond(c)
		return
	}
	if !session.Passed2FA {
		errs.IllegalStateError().AppendDetails("二次验证未通过", "二次验证失败").Respond(c)
		return
	}

	stepupToken, e := crypto2.GenerateJWT(uuid.New(), &model.TokenClaims{
		UserID:    claims.UserID,
		TokenType: model.TokenTypeStepup,
	}, cfg.C.StepupTokenTTL)
	if e != nil {
		errs.CreateAndLogInternalError(e, "Failed to generate stepup token").AppendDetails("令牌生成失败", "二次验证失败").Respond(c)
		return
	}

	if err := auth.DeleteAuthSession(c.Request.Context(), session); err != nil {
		slog.Warn("Failed to delete stepup auth session", "error", err.Info.Error, "session_id", session.ID)
	}

	maxAge := int(cfg.C.StepupTokenTTL.Seconds())
	setStepupCookie(c, stepupToken, maxAge)

	c.JSON(http.StatusOK, gin.H{})
}
