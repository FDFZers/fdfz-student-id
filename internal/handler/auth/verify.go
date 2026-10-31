package auth

import (
	"context"
	"crypto/subtle"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/service/auth"
	"fdfz-student-id/internal/service/email"
	qqservice "fdfz-student-id/internal/service/qq"
	"fdfz-student-id/internal/util/crypto"
	"log/slog"
	"net/http"
	"time"

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
		errs.RateLimitExceededError().AppendDetails("验证失败次数过多，请重新认证", item).Respond(c)
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
	if err := auth.TryAcquireEmailRateLimit(c.Request.Context(), session.Email.String); err != nil {
		err.AppendDetails("邮箱验证码发送失败").Respond(c)
		return
	}
	if !session.Email.Valid {
		if session.Type == auth.AuthSessionTypeResetPassword {
			// 重置密码静默成功防止账号枚举
			c.JSON(http.StatusOK, gin.H{})
			return
		}
		errs.IllegalStateError().AppendDetails("不支持邮箱验证", "邮箱验证码发送失败").Respond(c)
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
	if !check2FAAttempts(c, session, "邮箱验证失败") {
		return
	}
	if !session.Email.Valid {
		if session.Type == auth.AuthSessionTypeResetPassword {
			// 重置密码模糊错误防止账号枚举
			if !record2FAFailure(c, session, "邮箱验证失败") {
				return
			}
			errs.ForbiddenError().AppendDetails("验证码错误", "邮箱验证失败").Respond(c)
			return
		}
		errs.IllegalStateError().AppendDetails("不支持邮箱验证", "邮箱验证失败").Respond(c)
		return
	}
	if !session.EmailCode.Valid {
		if session.Type == auth.AuthSessionTypeResetPassword {
			if !record2FAFailure(c, session, "邮箱验证失败") {
				return
			}
			errs.ForbiddenError().AppendDetails("验证码错误", "邮箱验证失败").Respond(c)
			return
		}
		errs.IllegalStateError().AppendDetails("邮箱验证码未发送", "邮箱验证失败").Respond(c)
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

type verifyQQInitReq struct {
	SessionID uuid.UUID `json:"session_id"`
}

func verifyQQInitHandler(c *gin.Context) {
	var req verifyQQInitReq
	if err := c.ShouldBindJSON(&req); err != nil {
		errs.BadRequestError().AppendDetails("请求解析失败", "QQ 验证码初始化失败").Respond(c)
		return
	}

	session, err := auth.GetAuthSessionByID(c.Request.Context(), req.SessionID)
	if err != nil {
		err.AppendDetails("QQ 验证码初始化失败").Respond(c)
		return
	} else if session == nil {
		errs.NotFoundError().AppendDetails("鉴权会话不存在", "QQ 验证码初始化失败").Respond(c)
		return
	}

	if session.Passed2FA {
		errs.IllegalStateError().AppendDetails("二次验证已通过", "QQ 验证码初始化失败").Respond(c)
		return
	}
	if !session.QQ.Valid {
		if session.Type == auth.AuthSessionTypeResetPassword {
			// 重置密码静默成功防止账号枚举
			c.JSON(http.StatusOK, gin.H{})
			return
		}
		errs.IllegalStateError().AppendDetails("不支持 QQ 验证", "QQ 验证码初始化失败").Respond(c)
		return
	}
	if session.QQCode.Valid {
		if session.Type == auth.AuthSessionTypeResetPassword {
			// 重置密码静默成功防止账号枚举
			c.JSON(http.StatusOK, gin.H{})
			return
		}
		errs.IllegalStateError().AppendDetails("QQ 验证已初始化", "QQ 验证码初始化失败").Respond(c)
		return
	}

	code, e := crypto.GenerateCode(6, crypto.CodeCharset)
	if e != nil {
		errs.CreateAndLogInternalError(e, "Failed to generate code").AppendDetails("验证码生成失败", "QQ 验证码初始化失败").Respond(c)
		return
	}

	session.QQCode = null.StringFrom(code)
	if err := auth.UpdateAuthSession(c.Request.Context(), session, true); err != nil {
		errs.CreateAndLogInternalError(err, "Failed to update auth session").AppendDetails("二次验证更新失败", "QQ 验证码初始化失败").Respond(c)
		return
	}

	c.JSON(http.StatusOK, gin.H{})
}

type verifyQQReq struct {
	SessionID uuid.UUID `json:"session_id"`
	Code      string    `json:"code"`
}

func verifyQQHandler(c *gin.Context) {
	var req verifyQQReq
	if err := c.ShouldBindJSON(&req); err != nil {
		errs.BadRequestError().AppendDetails("请求解析失败", "QQ 验证失败").Respond(c)
		return
	}

	session, err := auth.GetAuthSessionByID(c.Request.Context(), req.SessionID)
	if err != nil {
		err.AppendDetails("QQ 验证失败").Respond(c)
		return
	} else if session == nil {
		errs.NotFoundError().AppendDetails("鉴权会话不存在", "QQ 验证失败").Respond(c)
		return
	}

	if session.Passed2FA {
		errs.IllegalStateError().AppendDetails("二次验证已通过", "QQ 验证失败").Respond(c)
		return
	}
	if !check2FAAttempts(c, session, "QQ 验证失败") {
		return
	}
	if err := auth.TryAcquireQQRateLimit(c.Request.Context(), session.QQ.String); err != nil {
		err.AppendDetails("QQ 验证码发送失败").Respond(c)
		return
	}
	if !session.Email.Valid {
		if session.Type == auth.AuthSessionTypeResetPassword {
			// 重置密码模糊错误防止账号枚举
			if !record2FAFailure(c, session, "QQ 验证失败") {
				return
			}
			errs.ForbiddenError().AppendDetails("验证码错误", "QQ 验证失败").Respond(c)
			return
		}
		errs.IllegalStateError().AppendDetails("不支持 QQ 验证", "QQ 验证失败").Respond(c)
		return
	}
	if !session.EmailCode.Valid {
		if session.Type == auth.AuthSessionTypeResetPassword {
			if !record2FAFailure(c, session, "QQ 验证失败") {
				return
			}
			errs.ForbiddenError().AppendDetails("验证码错误", "QQ 验证失败").Respond(c)
			return
		}
		errs.IllegalStateError().AppendDetails("QQ 验证码未初始化", "QQ 验证失败").Respond(c)
		return
	}

	pullCtx, cancel := context.WithTimeout(c.Request.Context(), auth.QQPullTimeout)
	defer cancel()

	messages, e := qqservice.GetFriendMsgHistory(pullCtx, session.QQ.String, 20)
	if e != nil {
		errs.CreateAndLogInternalError(e, "Failed to pull QQ messages from NapCat").AppendDetails("NapCat 错误", "QQ 验证失败").Respond(c)
		return
	}

	cutoff := time.Now().Add(-auth.AuthSession2FACacheDuration).Unix()
	success := false
	for _, msg := range messages {
		if msg.Time < cutoff {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(msg.Text), []byte(session.QQCode.String)) != 1 {
			continue
		}

		success = true
	}

	if !success {
		if !record2FAFailure(c, session, "QQ 验证失败") {
			return
		}
		errs.ForbiddenError().AppendDetails("未识别到验证码", "QQ 验证失败").Respond(c)
		return
	}

	// 刷新会话
	session, err = auth.GetAuthSessionByID(c.Request.Context(), session.ID)
	if err != nil {
		err.AppendDetails("QQ 验证失败").Respond(c)
		return
	} else if session == nil {
		errs.NotFoundError().AppendDetails("鉴权会话不存在", "QQ 验证失败").Respond(c)
		return
	} else if session.Passed2FA {
		errs.IllegalStateError().AppendDetails("二次验证已通过", "QQ 验证失败").Respond(c)
		return
	}
	if !complete2FA(c, session, "QQ 验证失败") {
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
