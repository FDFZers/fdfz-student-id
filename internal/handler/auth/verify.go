package auth

import (
	"context"
	"crypto/subtle"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/service/auth"
	"fdfz-student-id/internal/service/email"
	"fdfz-student-id/internal/service/qq"
	"fdfz-student-id/internal/util/crypto"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/guregu/null/v6"
)

func check2FAAttempts(ctx context.Context, session *auth.AuthSession) *errs.Error {
	attempts, err := auth.GetAuthSessionAttempts(ctx, session.ID)
	if err != nil {
		return err
	}
	if attempts >= auth.MaxAuthSessionAttempts {
		return errs.RateLimitExceededError().AppendDetails("验证失败次数过多，请重新认证")
	}
	return nil
}

func record2FAFailure(ctx context.Context, session *auth.AuthSession) *errs.Error {
	if _, err := auth.IncreaseAuthSessionAttempts(ctx, session.ID); err != nil {
		return err
	}
	return nil
}

func complete2FA(ctx context.Context, session *auth.AuthSession) *errs.Error {
	session.Passed2FA = true
	session.EmailCode = null.String{}
	session.QQCode = null.String{}
	if err := auth.UpdateAuthSession(ctx, session, false); err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to update auth session").AppendDetails("二次验证通过失败")
	}
	if err := auth.ResetAuthSessionAttempts(ctx, session.ID); err != nil {
		slog.Warn("Failed to reset auth session attempts", "error", err.Info.Error, "session_id", session.ID)
	}
	return nil
}

type verifyEmailInitReq struct {
	SessionID uuid.UUID `json:"session_id"`
}

func verifyEmailInitHandler(c *gin.Context) *errs.Error {
	var req verifyEmailInitReq
	if err := c.ShouldBindJSON(&req); err != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}

	session, err := auth.GetAuthSessionByID(c.Request.Context(), req.SessionID)
	if err != nil {
		return err
	} else if session == nil {
		return errs.NotFoundError().AppendDetails("鉴权会话不存在")
	}

	if session.Passed2FA {
		return errs.IllegalStateError().AppendDetails("二次验证已通过")
	}
	if err := auth.TryAcquireEmailRateLimit(c.Request.Context(), session.Email.String); err != nil {
		return err
	}
	if !session.Email.Valid {
		if session.Type == auth.AuthSessionTypeResetPassword {
			// 重置密码静默成功防止账号枚举
			c.JSON(http.StatusOK, gin.H{})
			return nil
		}
		return errs.IllegalStateError().AppendDetails("不支持邮箱验证")
	}

	code, e := crypto.GenerateCode(6, crypto.CodeCharset)
	if e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to generate code").AppendDetails("验证码生成失败")
	}

	if err := email.SendCode(session.Email.String, code, session.Type); err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to send email code").AppendDetails("邮件发送失败")
	}

	session.EmailCode = null.StringFrom(code)
	if err := auth.UpdateAuthSession(c.Request.Context(), session, true); err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to update auth session").AppendDetails("二次验证更新失败")
	}

	c.JSON(http.StatusOK, gin.H{})
	return nil
}

type verifyEmailReq struct {
	SessionID uuid.UUID `json:"session_id"`
	Code      string    `json:"code"`
}

func verifyEmailHandler(c *gin.Context) *errs.Error {
	var req verifyEmailReq
	if err := c.ShouldBindJSON(&req); err != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}

	session, err := auth.GetAuthSessionByID(c.Request.Context(), req.SessionID)
	if err != nil {
		return err
	} else if session == nil {
		return errs.NotFoundError().AppendDetails("鉴权会话不存在")
	}

	if session.Passed2FA {
		return errs.IllegalStateError().AppendDetails("二次验证已通过")
	}
	if err := check2FAAttempts(c.Request.Context(), session); err != nil {
		return err
	}
	if !session.Email.Valid {
		if session.Type == auth.AuthSessionTypeResetPassword {
			// 重置密码模糊错误防止账号枚举
			if err := record2FAFailure(c.Request.Context(), session); err != nil {
				return err
			}
			return errs.ForbiddenError().AppendDetails("验证码错误")
		}
		return errs.IllegalStateError().AppendDetails("不支持邮箱验证")
	}
	if !session.EmailCode.Valid {
		if session.Type == auth.AuthSessionTypeResetPassword {
			if err := record2FAFailure(c.Request.Context(), session); err != nil {
				return err
			}
			return errs.ForbiddenError().AppendDetails("验证码错误")
		}
		return errs.IllegalStateError().AppendDetails("邮箱验证码未发送")
	}

	if subtle.ConstantTimeCompare([]byte(session.EmailCode.String), []byte(req.Code)) != 1 {
		if err := record2FAFailure(c.Request.Context(), session); err != nil {
			return err
		}
		return errs.ForbiddenError().AppendDetails("验证码错误")
	}

	if err := complete2FA(c.Request.Context(), session); err != nil {
		return err
	}

	c.JSON(http.StatusOK, gin.H{})
	return nil
}

type verifyQQInitReq struct {
	SessionID uuid.UUID `json:"session_id"`
}

func verifyQQInitHandler(c *gin.Context) *errs.Error {
	var req verifyQQInitReq
	if err := c.ShouldBindJSON(&req); err != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}

	session, err := auth.GetAuthSessionByID(c.Request.Context(), req.SessionID)
	if err != nil {
		return err
	} else if session == nil {
		return errs.NotFoundError().AppendDetails("鉴权会话不存在")
	}

	if session.Passed2FA {
		return errs.IllegalStateError().AppendDetails("二次验证已通过")
	}
	if !session.QQ.Valid {
		if session.Type == auth.AuthSessionTypeResetPassword {
			// 重置密码静默成功防止账号枚举
			c.JSON(http.StatusOK, gin.H{})
			return nil
		}
		return errs.IllegalStateError().AppendDetails("不支持 QQ 验证")
	}
	if session.QQCode.Valid {
		c.JSON(http.StatusOK, gin.H{
			"code": session.QQCode.String,
		})
		return nil
	}

	code, e := crypto.GenerateCode(6, crypto.CodeCharset)
	if e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to generate code").AppendDetails("验证码生成失败")
	}

	session.QQCode = null.StringFrom(code)
	if err := auth.UpdateAuthSession(c.Request.Context(), session, true); err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to update auth session").AppendDetails("二次验证更新失败")
	}

	c.JSON(http.StatusOK, gin.H{
		"code": code,
	})
	return nil
}

type verifyQQReq struct {
	SessionID uuid.UUID `json:"session_id"`
	Code      string    `json:"code"`
}

func verifyQQHandler(c *gin.Context) *errs.Error {
	var req verifyQQReq
	if err := c.ShouldBindJSON(&req); err != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}

	session, err := auth.GetAuthSessionByID(c.Request.Context(), req.SessionID)
	if err != nil {
		return err
	} else if session == nil {
		return errs.NotFoundError().AppendDetails("鉴权会话不存在")
	}

	if session.Passed2FA {
		return errs.IllegalStateError().AppendDetails("二次验证已通过")
	}
	if err := check2FAAttempts(c.Request.Context(), session); err != nil {
		return err
	}
	if err := auth.TryAcquireQQRateLimit(c.Request.Context(), session.QQ.String); err != nil {
		return err.AppendDetails("QQ 验证码发送失败").Seal()
	}
	if !session.QQ.Valid {
		if session.Type == auth.AuthSessionTypeResetPassword {
			// 重置密码模糊错误防止账号枚举
			if err := record2FAFailure(c.Request.Context(), session); err != nil {
				return err
			}
			return errs.ForbiddenError().AppendDetails("验证码错误")
		}
		return errs.IllegalStateError().AppendDetails("不支持 QQ 验证")
	}
	if !session.QQCode.Valid {
		if session.Type == auth.AuthSessionTypeResetPassword {
			if err := record2FAFailure(c.Request.Context(), session); err != nil {
				return err
			}
			return errs.ForbiddenError().AppendDetails("验证码错误")
		}
		return errs.IllegalStateError().AppendDetails("QQ 验证码未初始化")
	}

	pullCtx, cancel := context.WithTimeout(c.Request.Context(), auth.QQPullTimeout)
	defer cancel()

	messages, e := qq.GetFriendMsgHistory(pullCtx, session.QQ.String, 20)
	if e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to pull QQ messages from NapCat").AppendDetails("NapCat 错误")
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
		if err := record2FAFailure(c.Request.Context(), session); err != nil {
			return err
		}
		return errs.ForbiddenError().AppendDetails("未识别到验证码")
	}

	// 刷新会话
	session, err = auth.GetAuthSessionByID(c.Request.Context(), session.ID)
	if err != nil {
		return err
	} else if session == nil {
		return errs.NotFoundError().AppendDetails("鉴权会话不存在")
	} else if session.Passed2FA {
		return errs.IllegalStateError().AppendDetails("二次验证已通过")
	}
	if err := complete2FA(c.Request.Context(), session); err != nil {
		return err
	}

	c.JSON(http.StatusOK, gin.H{})
	return nil
}

type verifyTOTPReq struct {
	Code      string    `json:"code"`
	SessionID uuid.UUID `json:"session_id"`
}

func verifyTOTPHandler(c *gin.Context) *errs.Error {
	var req verifyTOTPReq
	if err := c.ShouldBindJSON(&req); err != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}

	session, err := auth.GetAuthSessionByID(c.Request.Context(), req.SessionID)
	if err != nil {
		return err
	} else if session == nil {
		return errs.NotFoundError().AppendDetails("鉴权会话不存在")
	}

	if session.Passed2FA {
		return errs.IllegalStateError().AppendDetails("二次验证已通过")
	}
	if !session.TOTPSecret.Valid {
		return errs.IllegalStateError().AppendDetails("不支持 TOTP 验证")
	}
	if err := check2FAAttempts(c.Request.Context(), session); err != nil {
		return err
	}

	if ok, err := crypto.VerifyTOTP(session.TOTPSecret.String, req.Code); err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to verify TOTP").AppendDetails("TOTP 校验失败")
	} else if !ok {
		if err := record2FAFailure(c.Request.Context(), session); err != nil {
			return err
		}
		return errs.ForbiddenError().AppendDetails("验证码错误")
	}

	if err := complete2FA(c.Request.Context(), session); err != nil {
		return err
	}
	c.JSON(http.StatusOK, gin.H{})
	return nil
}
