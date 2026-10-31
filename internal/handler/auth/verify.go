package auth

import (
	"crypto/subtle"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/service/auth"
	"fdfz-student-id/internal/service/email"
	"fdfz-student-id/internal/util/crypto"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/guregu/null/v6"
)

func check2FAAttempts(c *gin.Context, session *auth.AuthSession, item string) bool {
	attempts, err := auth.GetAuthSessionAttempts(c.Request.Context(), session.ID)
	if err != nil {
		err.AppendDetails(item).Respond(c)
		return false
	}
	if attempts >= auth.MaxAuthSessionAttempts {
		errs.RateLimitExceededError().AppendDetails("验证失败次数过多，请重新使用密码登录", item).Respond(c)
		return false
	}
	return true
}

func record2FAFailure(c *gin.Context, session *auth.AuthSession, item string) bool {
	if _, err := auth.IncreaseAuthSessionAttempts(c.Request.Context(), session.ID); err != nil {
		err.AppendDetails(item).Respond(c)
		return false
	}
	return true
}

func complete2FA(c *gin.Context, session *auth.AuthSession, item string) bool {
	session.Passed2FA = true
	session.EmailCode = null.String{}
	if err := auth.UpdateAuthSession(c.Request.Context(), session, false); err != nil {
		errs.CreateAndLogInternalError(err, "Failed to update auth session").AppendDetails("二次验证通过失败", item).Respond(c)
		return false
	}
	if err := auth.ResetAuthSessionAttempts(c.Request.Context(), session.ID); err != nil {
		slog.Warn("Failed to reset auth session attempts", "error", err.Info.Error, "session_id", session.ID)
	}
	return true
}

type verifyEmailInitReq struct {
	SessionID uuid.UUID `json:"session_id"`
}

func verifyEmailInitHandler(c *gin.Context) {
	var req verifyEmailInitReq
	if err := c.ShouldBindJSON(&req); err != nil {
		errs.BadRequestError().AppendDetails("请求解析失败", "邮箱验证码发送失败").Respond(c)
		return
	}

	session, err := auth.GetAuthSessionByID(c.Request.Context(), req.SessionID)
	if err != nil {
		err.AppendDetails("邮箱验证码发送失败").Respond(c)
		return
	} else if session == nil {
		errs.NotFoundError().AppendDetails("鉴权会话不存在", "邮箱验证码发送失败").Respond(c)
		return
	}

	if session.Passed2FA {
		errs.IllegalStateError().AppendDetails("二次验证已通过", "邮箱验证码发送失败").Respond(c)
		return
	}
	if !session.Email.Valid {
		errs.IllegalStateError().AppendDetails("不支持邮箱验证", "邮箱验证码发送失败").Respond(c)
		return
	}
	if auth.ValidateEmailRateLimit(c.Request.Context(), session.Email.String) != nil {
		errs.RateLimitExceededError().AppendDetails("邮箱验证码发送失败").Respond(c)
		return
	}

	code, e := crypto.GenerateCode(6, crypto.CodeCharset)
	if e != nil {
		errs.CreateAndLogInternalError(e, "Failed to generate code").AppendDetails("验证码生成失败", "邮箱验证码发送失败").Respond(c)
		return
	}

	if err := email.SendCode(session.Email.String, code, session.Type); err != nil {
		errs.CreateAndLogInternalError(err, "Failed to send email code").AppendDetails("邮件发送失败", "邮箱验证码发送失败").Respond(c)
		return
	}

	session.EmailCode = null.StringFrom(code)
	if err := auth.UpdateAuthSession(c.Request.Context(), session, true); err != nil {
		errs.CreateAndLogInternalError(err, "Failed to update auth session").AppendDetails("二次验证更新失败", "邮箱验证码发送失败").Respond(c)
		return
	}

	auth.UpdateEmailLastSentAt(c.Request.Context(), session.Email.String)

	c.JSON(http.StatusOK, gin.H{})
}

type verifyEmailReq struct {
	SessionID uuid.UUID `json:"session_id"`
	Code      string    `json:"code"`
}

func verifyEmailHandler(c *gin.Context) {
	var req verifyEmailReq
	if err := c.ShouldBindJSON(&req); err != nil {
		errs.BadRequestError().AppendDetails("请求解析失败", "邮箱验证失败").Respond(c)
		return
	}

	session, err := auth.GetAuthSessionByID(c.Request.Context(), req.SessionID)
	if err != nil {
		err.AppendDetails("邮箱验证失败").Respond(c)
		return
	} else if session == nil {
		errs.NotFoundError().AppendDetails("鉴权会话不存在", "邮箱验证失败").Respond(c)
		return
	}

	if session.Passed2FA {
		errs.IllegalStateError().AppendDetails("二次验证已通过", "邮箱验证失败").Respond(c)
		return
	}
	if !session.Email.Valid {
		errs.IllegalStateError().AppendDetails("不支持邮箱验证", "邮箱验证失败").Respond(c)
		return
	}
	if !session.EmailCode.Valid {
		errs.IllegalStateError().AppendDetails("邮箱验证码未发送", "邮箱验证失败").Respond(c)
		return
	}
	if !check2FAAttempts(c, session, "邮箱验证失败") {
		return
	}

	if subtle.ConstantTimeCompare([]byte(session.EmailCode.String), []byte(req.Code)) != 1 {
		if !record2FAFailure(c, session, "邮箱验证失败") {
			return
		}
		errs.ForbiddenError().AppendDetails("验证码错误", "邮箱验证失败").Respond(c)
		return
	}

	if !complete2FA(c, session, "邮箱验证失败") {
		return
	}

	c.JSON(http.StatusOK, gin.H{})
}

type verifyTOTPReq struct {
	Code      string    `json:"code"`
	SessionID uuid.UUID `json:"session_id"`
}

func verifyTOTPHandler(c *gin.Context) {
	var req verifyTOTPReq
	if err := c.ShouldBindJSON(&req); err != nil {
		errs.BadRequestError().AppendDetails("请求解析失败", "TOTP 验证失败").Respond(c)
		return
	}

	session, err := auth.GetAuthSessionByID(c.Request.Context(), req.SessionID)
	if err != nil {
		err.AppendDetails("TOTP 验证失败").Respond(c)
		return
	} else if session == nil {
		errs.NotFoundError().AppendDetails("鉴权会话不存在", "TOTP 验证失败").Respond(c)
		return
	}

	if session.Passed2FA {
		errs.IllegalStateError().AppendDetails("二次验证已通过", "TOTP 验证失败").Respond(c)
		return
	}
	if !session.TOTPSecret.Valid {
		errs.IllegalStateError().AppendDetails("不支持 TOTP 验证", "TOTP 验证失败").Respond(c)
		return
	}
	if !check2FAAttempts(c, session, "TOTP 验证失败") {
		return
	}

	if ok, err := crypto.VerifyTOTP(session.TOTPSecret.String, req.Code); err != nil {
		errs.CreateAndLogInternalError(err, "Failed to verify TOTP").AppendDetails("TOTP 校验失败", "TOTP 验证失败").Respond(c)
		return
	} else if !ok {
		if !record2FAFailure(c, session, "TOTP 验证失败") {
			return
		}
		errs.ForbiddenError().AppendDetails("验证码错误", "TOTP 验证失败").Respond(c)
		return
	}

	if !complete2FA(c, session, "TOTP 验证失败") {
		return
	}
	c.JSON(http.StatusOK, gin.H{})
}
