package auth

import (
	"fdfz-student-id/internal/cfg"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/service/auth"
	"fdfz-student-id/internal/service/user"
	"fdfz-student-id/internal/util/crypto"
	"fdfz-student-id/internal/util/handling"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func stepupInitHandler(c *gin.Context) *errs.Error {
	claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)

	if claims.IsTemporary {
		return errs.PermissionDeniedError().AppendDetails("临时会话不支持二次验证")
	}

	ban, err := user.GetUserBan(c.Request.Context(), claims.UserID)
	if err != nil {
		return err
	}
	if ban != nil {
		return handling.BannedError(ban)
	}

	session, err := auth.CreateAuthSession(c.Request.Context(), auth.AuthSessionTypeStepup, false, claims.UserID, false)
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

type stepupFinalizeReq struct {
	SessionID uuid.UUID `json:"session_id"`
}

func stepupFinalizeHandler(c *gin.Context) *errs.Error {
	var req stepupFinalizeReq
	if err := c.ShouldBindJSON(&req); err != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}
	if req.SessionID == uuid.Nil {
		return errs.BadRequestError().AppendDetails("无效的鉴权会话 ID")
	}

	claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)

	session, err := auth.GetAuthSessionByID(c.Request.Context(), req.SessionID)
	if err != nil {
		return err
	} else if session == nil {
		return errs.NotFoundError().AppendDetails("鉴权会话不存在")
	}

	if session.Type != auth.AuthSessionTypeStepup {
		return errs.BadRequestError().AppendDetails("鉴权会话类型错误")
	}
	if session.UserID != claims.UserID {
		return errs.ForbiddenError().AppendDetails("鉴权会话不属于当前用户")
	}
	if !session.Passed2FA {
		return errs.IllegalStateError().AppendDetails("二次验证未通过")
	}

	stepupToken, e := crypto.GenerateJWT(uuid.New(), &model.TokenClaims{
		UserID:    claims.UserID,
		TokenType: model.TokenTypeStepup,
	}, cfg.C.StepupTokenTTL)
	if e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to generate stepup token").AppendDetails("令牌生成失败")
	}

	if err := auth.DeleteAuthSession(c.Request.Context(), session); err != nil {
		slog.Warn("Failed to delete stepup auth session", "error", err.Info.Error, "session_id", session.ID)
	}

	maxAge := int(cfg.C.StepupTokenTTL.Seconds())
	handling.SetStepupCookie(c, stepupToken, maxAge)

	c.JSON(http.StatusOK, gin.H{})
	return nil
}
