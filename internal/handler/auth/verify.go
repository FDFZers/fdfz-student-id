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

// check2FAAttempts 检查鉴权会话的二次验证失败次数，超过 MaxAuthSessionAttempts 时返回 429。
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

// record2FAFailure 记录一次二次验证失败，供 check2FAAttempts 限制暴力尝试。
func record2FAFailure(ctx context.Context, session *auth.AuthSession) *errs.Error {
	if _, err := auth.IncreaseAuthSessionAttempts(ctx, session.ID); err != nil {
		return err
	}
	return nil
}

// complete2FA 把鉴权会话标记为二次验证通过并清除已发送的验证码，同时重置失败计数。
// 注意：先更新会话（落 Redis）再重置计数，会话更新失败时不会清空失败次数。
func complete2FA(ctx context.Context, session *auth.AuthSession) *errs.Error {
	session.Passed2FA = true
	session.EmailCode = null.String{}
	session.QQCode = null.String{}
	if err := auth.UpdateAuthSession(ctx, session, false); err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to update auth session").AppendDetails("二次验证状态更新失败")
	}
	if err := auth.ResetAuthSessionAttempts(ctx, session.ID); err != nil {
		slog.Warn("Failed to reset auth session attempts", "error", err.Info.Error, "session_id", session.ID)
	}
	return nil
}

// verifyEmailInitReq 是发送邮箱验证码的请求体。
type verifyEmailInitReq struct {
	SessionID uuid.UUID `json:"session_id"` // 鉴权会话 ID
}

// verifyEmailInitHandler 向鉴权会话关联的邮箱发送登录/提权/密码重置验证码。
// 注意：密码重置的匿名会话会静默返回成功；已通过二次验证的会话拒绝重复发送。
func verifyEmailInitHandler(c *gin.Context) *errs.Error {
	var req verifyEmailInitReq
	if e := c.ShouldBindJSON(&req); e != nil {
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
	// 存疑：先占用发送冷却再判断会话是否有邮箱，密码重置的匿名会话会在空邮箱上消耗冷却窗口。
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

	// 生成验证码并发送邮件
	code, e := crypto.GenerateCode(6, crypto.CodeCharset)
	if e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to generate code").AppendDetails("验证码生成失败")
	}

	if e := email.SendCode(session.Email.String, code, session.Type); e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to send email code").AppendDetails("邮件发送失败")
	}

	session.EmailCode = null.StringFrom(code)
	if err := auth.UpdateAuthSession(c.Request.Context(), session, true); err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to update auth session").AppendDetails("二次验证状态更新失败")
	}

	c.JSON(http.StatusOK, gin.H{})
	return nil
}

// verifyEmailReq 是校验邮箱验证码的请求体。
type verifyEmailReq struct {
	SessionID uuid.UUID `json:"session_id"` // 鉴权会话 ID
	Code      string    `json:"code"`       // 邮箱验证码
}

// verifyEmailHandler 校验鉴权会话关联邮箱收到的验证码，通过后标记会话已通过二次验证。
// 注意：密码重置流程在无邮箱或未发送验证码时统一返回「验证码错误」，防止账号枚举。
func verifyEmailHandler(c *gin.Context) *errs.Error {
	var req verifyEmailReq
	if e := c.ShouldBindJSON(&req); e != nil {
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

	// 常量时间比较，避免通过响应耗时逐位猜测验证码
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

// verifyQQInitReq 是初始化 QQ 验证码的请求体。
type verifyQQInitReq struct {
	SessionID uuid.UUID `json:"session_id"` // 鉴权会话 ID
}

// verifyQQInitHandler 生成 QQ 验证码并返回给调用方，由用户主动私聊 NapCat 机器人发送该验证码。
// 注意：已有验证码时直接返回原验证码，不重复生成；匿名密码重置会话静默成功。
func verifyQQInitHandler(c *gin.Context) *errs.Error {
	var req verifyQQInitReq
	if e := c.ShouldBindJSON(&req); e != nil {
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

	// 生成验证码并写回鉴权会话，延长其缓存时间
	code, e := crypto.GenerateCode(6, crypto.CodeCharset)
	if e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to generate code").AppendDetails("验证码生成失败")
	}

	session.QQCode = null.StringFrom(code)
	if err := auth.UpdateAuthSession(c.Request.Context(), session, true); err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to update auth session").AppendDetails("二次验证状态更新失败")
	}

	c.JSON(http.StatusOK, gin.H{
		"code": code,
	})
	return nil
}

// verifyQQReq 是校验 QQ 验证码的请求体。
type verifyQQReq struct {
	SessionID uuid.UUID `json:"session_id"` // 鉴权会话 ID
	Code      string    `json:"code"`       // 用户私聊机器人发送的验证码
}

// verifyQQHandler 拉取 NapCat 最近的好友消息，匹配用户发送的验证码，通过后标记会话已通过二次验证。
// 注意：只接受最近 AuthSession2FACacheDuration 内、文本与验证码完全一致的消息。
func verifyQQHandler(c *gin.Context) *errs.Error {
	var req verifyQQReq
	if e := c.ShouldBindJSON(&req); e != nil {
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
	// 存疑：先占用 QQ 拉取冷却再判断会话是否有 QQ，匿名重置会话会在空 QQ 号上消耗冷却窗口。
	if err := auth.TryAcquireQQRateLimit(c.Request.Context(), session.QQ.String); err != nil {
		return err
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

	// 拉取最近 20 条好友消息，只比对时间窗口内的文本
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

	// 重新读取会话，避免匹配消息期间会话已被其他请求更新或删除
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

// verifyTOTPReq 是校验 TOTP 验证码的请求体。
type verifyTOTPReq struct {
	Code      string    `json:"code"`       // TOTP 验证码
	SessionID uuid.UUID `json:"session_id"` // 鉴权会话 ID
}

// verifyTOTPHandler 校验鉴权会话对应用户的 TOTP 验证码，通过后标记会话已通过二次验证。
func verifyTOTPHandler(c *gin.Context) *errs.Error {
	var req verifyTOTPReq
	if e := c.ShouldBindJSON(&req); e != nil {
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

	if ok, e := crypto.VerifyTOTP(session.TOTPSecret.String, req.Code); e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to verify TOTP").AppendDetails("TOTP 校验失败")
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
