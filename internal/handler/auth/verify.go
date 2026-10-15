package auth

import (
	"fdfz-student-id/internal/cfg"
	"fdfz-student-id/internal/crypto"
	"fdfz-student-id/internal/email"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/service/auth"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/guregu/null/v6"
)

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
	if session.LastSentAt.Add(cfg.C.CodeSendInterval).After(time.Now()) {
		errs.RateLimitExceededError().AppendDetails("验证码发送频率过高", "邮箱验证码发送失败").Respond(c)
		return
	}

	code, cErr := crypto.GenerateCode(6, crypto.CodeCharset)
	if cErr != nil {
		errs.CreateAndLogInternalError(cErr, "Failed to generate code").AppendDetails("验证码生成失败", "邮箱验证码发送失败").Respond(c)
		return
	}

	if err := email.SendCode(session.Email.String, code, session.Type); err != nil {
		errs.CreateAndLogInternalError(err, "Failed to send email code").AppendDetails("邮件发送失败", "邮箱验证码发送失败").Respond(c)
		return
	}

	session.EmailCode = null.StringFrom(code)
	session.LastSentAt = time.Now()
	if err := auth.UpdateAuthSession(c.Request.Context(), session, true); err != nil {
		errs.CreateAndLogInternalError(err, "Failed to update auth session").AppendDetails("二次验证更新失败", "邮箱验证码发送失败").Respond(c)
		return
	}

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
	}

	if session.EmailCode.String != req.Code {
		errs.ForbiddenError().AppendDetails("验证码错误", "邮箱验证失败").Respond(c)
		return
	}

	session.Passed2FA = true
	if err := auth.UpdateAuthSession(c.Request.Context(), session, false); err != nil {
		errs.CreateAndLogInternalError(err, "Failed to update auth session").AppendDetails("二次验证通过失败", "邮箱验证失败").Respond(c)
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

	if ok, err := crypto.VerifyTOTP(session.TOTPSecret.String, req.Code); err != nil {
		errs.CreateAndLogInternalError(err, "Failed to verify TOTP").AppendDetails("TOTP 校验失败", "TOTP 验证失败").Respond(c)
		return
	} else if !ok {
		errs.ForbiddenError().AppendDetails("验证码错误", "TOTP 验证失败").Respond(c)
		return
	}

	session.Passed2FA = true
	if err := auth.UpdateAuthSession(c.Request.Context(), session, false); err != nil {
		errs.CreateAndLogInternalError(err, "Failed to update auth session").AppendDetails("二次验证通过失败", "TOTP 验证失败").Respond(c)
		return
	}
	c.JSON(http.StatusOK, gin.H{})
}
