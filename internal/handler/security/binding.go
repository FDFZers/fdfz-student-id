package security

import (
	"context"
	"crypto/subtle"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/service/auth"
	"fdfz-student-id/internal/service/email"
	"fdfz-student-id/internal/service/qq"
	"fdfz-student-id/internal/service/user"
	"fdfz-student-id/internal/util/crypto"
	"fdfz-student-id/internal/util/handling"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type emailBindInitReq struct {
	Email string `json:"email"`
}

func emailBindInitHandler(c *gin.Context) *errs.Error {
	var req emailBindInitReq
	if err := c.ShouldBindJSON(&req); err != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}
	if err := handling.ValidateEmail(req.Email); err != nil {
		return err
	}

	claims := handling.MustGetClaims(c)

	current, err := user.GetUserEmail(c.Request.Context(), claims.UserID)
	if err != nil {
		return err
	}
	if current != nil && strings.EqualFold(current.Email, req.Email) {
		return errs.ConflictError().AppendDetails("该邮箱已绑定")
	}

	taken, err := user.IsEmailTaken(c.Request.Context(), req.Email)
	if err != nil {
		return err
	}
	if taken {
		return errs.ConflictError().AppendDetails("该邮箱已被其他用户绑定")
	}

	if err := auth.TryAcquireEmailRateLimit(c.Request.Context(), req.Email); err != nil {
		return err
	}

	if err := auth.TryAcquireEmailBindQuota(c.Request.Context(), claims.UserID); err != nil {
		return err
	}

	code, e := crypto.GenerateCode(6, crypto.CodeCharset)
	if e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to generate email bind code").
			AppendDetails("验证码生成失败")
	}

	if err := auth.SetPendingEmailBind(c.Request.Context(), claims.UserID, req.Email, code); err != nil {
		return err
	}

	if err := email.SendBindEmailCode(req.Email, code); err != nil {
		auth.DeletePendingEmailBind(c.Request.Context(), claims.UserID)
		return errs.CreateAndLogInternalError(err, "Failed to send email bind code").
			AppendDetails("邮件发送失败")
	}

	c.JSON(http.StatusOK, gin.H{})
	return nil
}

type emailBindVerifyReq struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

func emailBindVerifyHandler(c *gin.Context) *errs.Error {
	var req emailBindVerifyReq
	if err := c.ShouldBindJSON(&req); err != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}
	if err := handling.ValidateEmail(req.Email); err != nil {
		return err
	}
	if req.Code == "" {
		return errs.BadRequestError().AppendDetails("验证码不能为空")
	}

	claims := handling.MustGetClaims(c)

	pending, err := auth.GetPendingEmailBind(c.Request.Context(), claims.UserID)
	if err != nil {
		return err
	} else if pending == nil {
		return errs.IllegalStateError().AppendDetails("邮箱绑定未发起或已过期")
	}
	if !strings.EqualFold(pending.Email, req.Email) {
		return errs.BadRequestError().AppendDetails("邮箱与绑定请求不一致")
	}

	if err := checkBindAttempts(c.Request.Context(), bindEmailAttemptsKind, claims.UserID); err != nil {
		return err
	}

	if subtle.ConstantTimeCompare([]byte(pending.Code), []byte(req.Code)) != 1 {
		if err := recordBindFailure(c.Request.Context(), bindEmailAttemptsKind, claims.UserID); err != nil {
			return err
		}
		return errs.ForbiddenError().AppendDetails("验证码错误")
	}

	if err := user.SetUserEmail(c.Request.Context(), &model.UserEmail{
		UserID: claims.UserID,
		Email:  pending.Email,
	}); err != nil {
		return err
	}

	auth.DeletePendingEmailBind(c.Request.Context(), claims.UserID)
	auth.ResetBindAttempts(c.Request.Context(), bindEmailAttemptsKind, claims.UserID)

	c.JSON(http.StatusOK, gin.H{})
	return nil
}

func emailUnbindHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)
	current, err := user.GetUserEmail(c.Request.Context(), claims.UserID)
	if err != nil {
		return err
	} else if current == nil {
		return errs.NotFoundError().AppendDetails("未绑定邮箱")
	}

	if err := user.DeleteUserEmail(c.Request.Context(), claims.UserID); err != nil {
		return err
	}

	c.JSON(http.StatusOK, gin.H{})
	return nil
}

func totpBindInitHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)
	existing, err := user.GetUserTOTP(c.Request.Context(), claims.UserID)
	if err != nil {
		return err
	} else if existing != nil {
		return errs.ConflictError().AppendDetails("已绑定 TOTP")
	}

	secret, otpAuthURL, e := crypto.GenerateTOTP(uint64(claims.UserID))
	if e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to generate TOTP secret").
			AppendDetails("TOTP 密钥生成失败")
	}

	if err := auth.SetPendingTOTPBind(c.Request.Context(), claims.UserID, secret); err != nil {
		return err
	}

	c.JSON(http.StatusOK, gin.H{
		"secret": secret,
		"url":    otpAuthURL,
	})
	return nil
}

type totpBindVerifyReq struct {
	Code string `json:"code"`
}

func totpBindVerifyHandler(c *gin.Context) *errs.Error {
	var req totpBindVerifyReq
	if err := c.ShouldBindJSON(&req); err != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}
	if err := handling.ValidateTOTPCode(req.Code); err != nil {
		return err
	}

	claims := handling.MustGetClaims(c)

	pending, err := auth.GetPendingTOTPBind(c.Request.Context(), claims.UserID)
	if err != nil {
		return err
	} else if pending == nil {
		return errs.IllegalStateError().AppendDetails("TOTP 绑定未发起或已过期")
	}

	if err := checkBindAttempts(c.Request.Context(), bindTOTPAttemptsKind, claims.UserID); err != nil {
		return err
	}

	ok2, e := crypto.VerifyTOTP(pending.Secret, req.Code)
	if e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to verify TOTP code").
			AppendDetails("TOTP 校验失败")
	}
	if !ok2 {
		if err := recordBindFailure(c.Request.Context(), bindTOTPAttemptsKind, claims.UserID); err != nil {
			return err
		}
		return errs.ForbiddenError().AppendDetails("验证码错误")
	}

	if err := user.UpsertUserTotp(c.Request.Context(), &model.UserTOTP{
		UserID: claims.UserID,
		Secret: pending.Secret,
	}); err != nil {
		return err
	}

	auth.DeletePendingTOTPBind(c.Request.Context(), claims.UserID)
	auth.ResetBindAttempts(c.Request.Context(), bindTOTPAttemptsKind, claims.UserID)

	c.JSON(http.StatusOK, gin.H{})
	return nil
}

func totpUnbindHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)
	existing, err := user.GetUserTOTP(c.Request.Context(), claims.UserID)
	if err != nil {
		return err
	} else if existing == nil {
		return errs.NotFoundError().AppendDetails("未绑定 TOTP")
	}

	if err := user.DeleteUserTotp(c.Request.Context(), claims.UserID); err != nil {
		return err
	}

	c.JSON(http.StatusOK, gin.H{})
	return nil
}

type qqBindInitReq struct {
	QQ string `json:"qq"`
}

func qqBindInitHandler(c *gin.Context) *errs.Error {
	var req qqBindInitReq
	if err := c.ShouldBindJSON(&req); err != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}
	if err := handling.ValidateQQ(req.QQ); err != nil {
		return err
	}

	claims := handling.MustGetClaims(c)

	current, err := user.GetUserQQ(c.Request.Context(), claims.UserID)
	if err != nil {
		return err
	}
	if current != nil && current.QQ == req.QQ {
		return errs.ConflictError().AppendDetails("该 QQ 已绑定")
	}

	taken, err := user.IsQQTaken(c.Request.Context(), req.QQ)
	if err != nil {
		return err
	}
	if taken {
		return errs.ConflictError().AppendDetails("该 QQ 已被其他用户绑定")
	}

	code, e := crypto.GenerateCode(6, crypto.CodeCharset)
	if e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to generate QQ bind code").
			AppendDetails("验证码生成失败")
	}

	if err := auth.SetPendingQQBind(c.Request.Context(), claims.UserID, req.QQ, code); err != nil {
		return err
	}

	// 验证码由用户使用待绑定的 QQ 主动发送给机器人，服务端拉取好友消息进行校验
	c.JSON(http.StatusOK, gin.H{
		"code": code,
	})
	return nil
}

type qqBindVerifyReq struct {
	QQ string `json:"qq"`
}

func qqBindVerifyHandler(c *gin.Context) *errs.Error {
	var req qqBindVerifyReq
	if err := c.ShouldBindJSON(&req); err != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}
	if err := handling.ValidateQQ(req.QQ); err != nil {
		return err
	}

	claims := handling.MustGetClaims(c)

	pending, err := auth.GetPendingQQBind(c.Request.Context(), claims.UserID)
	if err != nil {
		return err
	} else if pending == nil {
		return errs.IllegalStateError().AppendDetails("QQ 绑定未发起或已过期")
	}
	if pending.QQ != req.QQ {
		return errs.BadRequestError().AppendDetails("QQ 与绑定请求不一致")
	}

	if err := checkBindAttempts(c.Request.Context(), bindQQAttemptsKind, claims.UserID); err != nil {
		return err
	}

	if err := auth.TryAcquireQQRateLimit(c.Request.Context(), pending.QQ); err != nil {
		return err
	}

	pullCtx, cancel := context.WithTimeout(c.Request.Context(), auth.QQPullTimeout)
	defer cancel()

	messages, e := qq.GetFriendMsgHistory(pullCtx, pending.QQ, 20)
	if e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to pull QQ messages from NapCat").
			AppendDetails("NapCat 错误")
	}

	cutoff := time.Now().Add(-auth.PendingBindDuration).Unix()
	matched := false
	for _, msg := range messages {
		if msg.Time < cutoff {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(msg.Text), []byte(pending.Code)) == 1 {
			matched = true
			break
		}
	}

	if !matched {
		if err := recordBindFailure(c.Request.Context(), bindQQAttemptsKind, claims.UserID); err != nil {
			return err
		}
		return errs.ForbiddenError().
			AppendDetails("未识别到验证码，请使用该 QQ 向机器人发送验证码")
	}

	if err := user.SetUserQQ(c.Request.Context(), &model.UserQQ{
		UserID: claims.UserID,
		QQ:     pending.QQ,
	}); err != nil {
		return err
	}

	auth.DeletePendingQQBind(c.Request.Context(), claims.UserID)
	auth.ResetBindAttempts(c.Request.Context(), bindQQAttemptsKind, claims.UserID)

	c.JSON(http.StatusOK, gin.H{})
	return nil
}

func qqUnbindHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)
	current, err := user.GetUserQQ(c.Request.Context(), claims.UserID)
	if err != nil {
		return err
	} else if current == nil {
		return errs.NotFoundError().AppendDetails("未绑定 QQ")
	}

	if err := user.DeleteUserQQ(c.Request.Context(), claims.UserID); err != nil {
		return err
	}

	c.JSON(http.StatusOK, gin.H{})
	return nil
}

func checkBindAttempts(ctx context.Context, kind string, userID int64) *errs.Error {
	attempts, err := auth.GetBindAttempts(ctx, kind, userID)
	if err != nil {
		return err.AppendDetails("绑定失败").Seal()
	}
	if attempts >= auth.MaxBindAttempts {
		return errs.RateLimitExceededError().
			AppendDetails("验证码错误次数过多，请重新发起绑定", "绑定失败").Seal()
	}
	return nil
}

func recordBindFailure(ctx context.Context, kind string, userID int64) *errs.Error {
	if _, err := auth.IncreaseBindAttempts(ctx, kind, userID); err != nil {
		return err.AppendDetails("绑定失败").Seal()
	}
	return nil
}
