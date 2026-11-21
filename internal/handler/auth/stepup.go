package auth

import (
	"fdfz-student-id/internal/cfg"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	authsvc "fdfz-student-id/internal/service/auth"
	usersvc "fdfz-student-id/internal/service/user"
	"fdfz-student-id/internal/util/crypto"
	"fdfz-student-id/internal/util/handling"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/guregu/null/v6"
)

// stepupInitHandler 为当前登录用户创建提权用鉴权会话，强制启用全部已绑定的二次验证方式。
// 注意：关闭「登录二次验证」只影响登录，提权仍按已绑定的方式校验；临时会话不允许提权。
func stepupInitHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)

	if claims.IsTemporary {
		return errs.PermissionDeniedError().AppendDetails("临时会话不支持二次验证")
	}

	ban, err := usersvc.GetUserBan(c.Request.Context(), claims.UserID)
	if err != nil {
		return err
	}
	if ban != nil {
		return handling.BannedError(ban)
	}

	// 提权始终按已绑定的方式校验，不受「登录二次验证」开关影响
	session, err := authsvc.CreateAuthSession(c.Request.Context(), authsvc.AuthSessionTypeStepup, false, claims.UserID, false, true)
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

// stepupFinalizeReq 是提权完成的请求体。
type stepupFinalizeReq struct {
	SessionID uuid.UUID `json:"session_id"` // 提权初始化返回的鉴权会话 ID
}

// stepupFinalizeHandler 在提权会话通过二次验证后签发短时效 stepup_token 并写入 Cookie。
// 注意：会话必须属于当前用户且已通过二次验证；签发后删除鉴权会话，提权令牌由 Cookie 承载。
func stepupFinalizeHandler(c *gin.Context) *errs.Error {
	var req stepupFinalizeReq
	if err := handling.BindJSON(c, &req); err != nil {
		return err
	}
	if err := handling.ValidateUUID(req.SessionID, "鉴权会话 ID"); err != nil {
		return err
	}

	claims := handling.MustGetClaims(c)

	// 校验提权会话的归属与状态
	session, err := authsvc.GetAuthSessionByID(c.Request.Context(), req.SessionID)
	if err != nil {
		return err
	} else if session == nil {
		return errs.NotFoundError().AppendDetails("鉴权会话不存在")
	}

	if session.Type != authsvc.AuthSessionTypeStepup {
		return errs.BadRequestError().AppendDetails("鉴权会话类型错误")
	}
	if session.UserID != claims.UserID {
		return errs.ForbiddenError().AppendDetails("鉴权会话不属于当前用户")
	}
	if !session.Passed2FA {
		return errs.IllegalStateError().AppendDetails("二次验证未通过")
	}

	// 签发提权令牌并写入 Cookie
	stepupToken, e := crypto.GenerateJWT(uuid.New(), &model.TokenClaims{
		UserID:    claims.UserID,
		TokenType: model.TokenTypeStepup,
		SessionID: null.StringFrom(claims.ID),
	}, cfg.C.StepupTokenTTL)
	if e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to generate stepup token").AppendDetails("令牌生成失败")
	}

	if err := authsvc.DeleteAuthSession(c.Request.Context(), session); err != nil {
		slog.Warn("Failed to delete stepup auth session", "error", err.Info.Error, "session_id", session.ID)
	}

	maxAge := int(cfg.C.StepupTokenTTL.Seconds())
	handling.SetStepupCookie(c, stepupToken, maxAge)

	handling.RespondOK(c)
	return nil
}
