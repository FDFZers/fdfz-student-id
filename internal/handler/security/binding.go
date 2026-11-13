package security

import (
	"context"
	"crypto/subtle"
	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	authsvc "fdfz-student-id/internal/service/auth"
	emailsvc "fdfz-student-id/internal/service/email"
	qqsvc "fdfz-student-id/internal/service/qq"
	usersvc "fdfz-student-id/internal/service/user"
	"fdfz-student-id/internal/util/crypto"
	"fdfz-student-id/internal/util/handling"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// emailBindInitReq 邮箱绑定发起请求体。
type emailBindInitReq struct {
	Email string `json:"email"`
}

// emailBindInitHandler 发起邮箱绑定：检查邮箱可用后生成验证码，暂存待绑定记录并发送邮件。
func emailBindInitHandler(c *gin.Context) *errs.Error {
	var req emailBindInitReq
	if err := handling.BindJSON(c, &req); err != nil {
		return err
	}
	if err := handling.ValidateEmail(req.Email); err != nil {
		return err
	}

	claims := handling.MustGetClaims(c)

	// 校验邮箱是否已绑定当前用户或已被其他用户占用
	current, err := usersvc.GetUserEmail(c.Request.Context(), claims.UserID)
	if err != nil {
		return err
	}
	if current != nil && strings.EqualFold(current.Email, req.Email) {
		return errs.ConflictError().AppendDetails("该邮箱已绑定")
	}

	taken, err := usersvc.IsEmailTaken(c.Request.Context(), req.Email)
	if err != nil {
		return err
	}
	if taken {
		return errs.ConflictError().AppendDetails("该邮箱已被其他用户绑定")
	}

	// 检查邮箱发送频控与用户、全站发送配额
	if err := authsvc.TryAcquireEmailRateLimit(c.Request.Context(), req.Email); err != nil {
		return err
	}

	if err := authsvc.TryAcquireEmailBindQuota(c.Request.Context(), claims.UserID); err != nil {
		return err
	}

	// 生成验证码并暂存待绑定记录，10 分钟内有效
	code, e := crypto.GenerateCode(6, crypto.CodeCharset)
	if e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to generate email bind code").
			AppendDetails("验证码生成失败")
	}

	if err := authsvc.SetPendingEmailBind(c.Request.Context(), claims.UserID, req.Email, code); err != nil {
		return err
	}

	// 邮件发送失败时清除待绑定记录，避免用户拿到无法校验的验证码
	if e := emailsvc.SendBindEmailCode(req.Email, code); e != nil {
		authsvc.DeletePendingEmailBind(c.Request.Context(), claims.UserID)
		return errs.CreateAndLogInternalError(e, "Failed to send email bind code").
			AppendDetails("邮件发送失败")
	}

	handling.RespondOK(c)
	return nil
}

// emailBindVerifyReq 邮箱绑定校验请求体。
type emailBindVerifyReq struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

// emailBindVerifyHandler 校验邮箱绑定验证码：通过后把邮箱写入用户邮箱表，并清理待绑定状态。
func emailBindVerifyHandler(c *gin.Context) *errs.Error {
	var req emailBindVerifyReq
	if err := handling.BindJSON(c, &req); err != nil {
		return err
	}
	if err := handling.ValidateEmail(req.Email); err != nil {
		return err
	}
	if err := handling.ValidateVerificationCode(req.Code); err != nil {
		return err
	}

	claims := handling.MustGetClaims(c)

	// 读取待绑定记录，未发起或已过期时拒绝
	pending, err := authsvc.GetPendingEmailBind(c.Request.Context(), claims.UserID)
	if err != nil {
		return err
	} else if pending == nil {
		return errs.IllegalStateError().AppendDetails("邮箱绑定未发起或已过期")
	}

	// 请求邮箱必须与待绑定记录一致，避免校验通过后绑定到其他邮箱
	if !strings.EqualFold(pending.Email, req.Email) {
		return errs.BadRequestError().AppendDetails("邮箱与绑定请求不一致")
	}

	if err := checkBindAttempts(c.Request.Context(), bindEmailAttemptsKind, claims.UserID); err != nil {
		return err
	}

	// 常量时间比较验证码，错误时累计失败次数
	if subtle.ConstantTimeCompare([]byte(pending.Code), []byte(req.Code)) != 1 {
		if err := recordBindFailure(c.Request.Context(), bindEmailAttemptsKind, claims.UserID); err != nil {
			return err
		}
		return errs.ForbiddenError().AppendDetails("验证码错误")
	}

	// 校验通过：换绑邮箱（旧记录软删除）并清理待绑定状态与失败计数
	if err := usersvc.SetUserEmail(c.Request.Context(), db.R, &model.UserEmail{
		UserID: claims.UserID,
		Email:  pending.Email,
	}); err != nil {
		return err
	}

	authsvc.DeletePendingEmailBind(c.Request.Context(), claims.UserID)
	authsvc.ResetBindAttempts(c.Request.Context(), bindEmailAttemptsKind, claims.UserID)

	handling.RespondOK(c)
	return nil
}

// emailUnbindHandler 解绑当前用户的邮箱：邮箱记录软删除，保留历史。
func emailUnbindHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)
	current, err := usersvc.GetUserEmail(c.Request.Context(), claims.UserID)
	if err != nil {
		return err
	} else if current == nil {
		return errs.NotFoundError().AppendDetails("未绑定邮箱")
	}

	if err := usersvc.DeleteUserEmail(c.Request.Context(), claims.UserID); err != nil {
		return err
	}

	handling.RespondOK(c)
	return nil
}

// totpBindInitHandler 发起 TOTP 绑定：生成密钥与 otpauth URL，并暂存待校验密钥。
func totpBindInitHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)
	existing, err := usersvc.GetUserTOTP(c.Request.Context(), claims.UserID)
	if err != nil {
		return err
	} else if existing != nil {
		return errs.ConflictError().AppendDetails("TOTP 已绑定")
	}

	// 生成密钥并暂存待绑定记录，10 分钟内未校验即失效
	secret, otpAuthURL, e := crypto.GenerateTOTP(uint64(claims.UserID))
	if e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to generate TOTP secret").
			AppendDetails("TOTP 密钥生成失败")
	}

	if err := authsvc.SetPendingTOTPBind(c.Request.Context(), claims.UserID, secret); err != nil {
		return err
	}

	// secret 与 url 一次性返回给前端展示，后续校验只比对 secret
	c.JSON(http.StatusOK, gin.H{
		"secret": secret,
		"url":    otpAuthURL,
	})
	return nil
}

// totpBindVerifyReq TOTP 绑定校验请求体。
type totpBindVerifyReq struct {
	Code string `json:"code"`
}

// totpBindVerifyHandler 校验 TOTP 验证码：通过后把密钥写入用户 TOTP 表，并清理待绑定状态。
func totpBindVerifyHandler(c *gin.Context) *errs.Error {
	var req totpBindVerifyReq
	if err := handling.BindJSON(c, &req); err != nil {
		return err
	}
	if err := handling.ValidateTOTPCode(req.Code); err != nil {
		return err
	}

	claims := handling.MustGetClaims(c)

	// 读取待校验密钥，未发起或已过期时拒绝
	pending, err := authsvc.GetPendingTOTPBind(c.Request.Context(), claims.UserID)
	if err != nil {
		return err
	} else if pending == nil {
		return errs.IllegalStateError().AppendDetails("TOTP 绑定未发起或已过期")
	}

	if err := checkBindAttempts(c.Request.Context(), bindTOTPAttemptsKind, claims.UserID); err != nil {
		return err
	}

	// 校验 TOTP，允许 1 个周期的时钟偏差；错误时累计失败次数
	valid, e := crypto.VerifyTOTP(pending.Secret, req.Code)
	if e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to verify TOTP code").
			AppendDetails("TOTP 校验失败")
	}
	if !valid {
		if err := recordBindFailure(c.Request.Context(), bindTOTPAttemptsKind, claims.UserID); err != nil {
			return err
		}
		return errs.ForbiddenError().AppendDetails("验证码错误")
	}

	// 校验通过：写入密钥并清理待绑定状态与失败计数
	if err := usersvc.UpsertUserTotp(c.Request.Context(), &model.UserTOTP{
		UserID: claims.UserID,
		Secret: pending.Secret,
	}); err != nil {
		return err
	}

	authsvc.DeletePendingTOTPBind(c.Request.Context(), claims.UserID)
	authsvc.ResetBindAttempts(c.Request.Context(), bindTOTPAttemptsKind, claims.UserID)

	handling.RespondOK(c)
	return nil
}

// totpUnbindHandler 解绑当前用户的 TOTP：直接删除密钥记录。
func totpUnbindHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)
	existing, err := usersvc.GetUserTOTP(c.Request.Context(), claims.UserID)
	if err != nil {
		return err
	} else if existing == nil {
		return errs.NotFoundError().AppendDetails("未绑定 TOTP")
	}

	if err := usersvc.DeleteUserTotp(c.Request.Context(), claims.UserID); err != nil {
		return err
	}

	handling.RespondOK(c)
	return nil
}

// qqBindInitReq QQ 绑定发起请求体。
type qqBindInitReq struct {
	QQ string `json:"qq"`
}

// qqBindInitHandler 发起 QQ 绑定：检查 QQ 可用后生成验证码并暂存，验证码返回给用户自行发送。
func qqBindInitHandler(c *gin.Context) *errs.Error {
	var req qqBindInitReq
	if err := handling.BindJSON(c, &req); err != nil {
		return err
	}
	if err := handling.ValidateQQ(req.QQ); err != nil {
		return err
	}

	claims := handling.MustGetClaims(c)

	// 校验 QQ 是否已绑定当前用户或已被其他用户占用
	current, err := usersvc.GetUserQQ(c.Request.Context(), claims.UserID)
	if err != nil {
		return err
	}
	if current != nil && current.QQ == req.QQ {
		return errs.ConflictError().AppendDetails("该 QQ 已绑定")
	}

	taken, err := usersvc.IsQQTaken(c.Request.Context(), req.QQ)
	if err != nil {
		return err
	}
	if taken {
		return errs.ConflictError().AppendDetails("该 QQ 已被其他用户绑定")
	}

	// 生成验证码并暂存待绑定记录，10 分钟内有效
	code, e := crypto.GenerateCode(6, crypto.CodeCharset)
	if e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to generate QQ bind code").
			AppendDetails("验证码生成失败")
	}

	if err := authsvc.SetPendingQQBind(c.Request.Context(), claims.UserID, req.QQ, code); err != nil {
		return err
	}

	// 验证码由用户使用待绑定的 QQ 主动发送给机器人，服务端稍后拉取好友消息校验
	c.JSON(http.StatusOK, gin.H{
		"code": code,
	})
	return nil
}

// qqBindVerifyReq QQ 绑定校验请求体。
type qqBindVerifyReq struct {
	QQ string `json:"qq"`
}

// qqBindVerifyHandler 校验 QQ 绑定：拉取 NapCat 好友消息，在待绑定有效期内匹配验证码。
// 注意：只认待绑定发起后 PendingBindDuration 内的消息，避免历史消息被重放。
func qqBindVerifyHandler(c *gin.Context) *errs.Error {
	var req qqBindVerifyReq
	if err := handling.BindJSON(c, &req); err != nil {
		return err
	}
	if err := handling.ValidateQQ(req.QQ); err != nil {
		return err
	}

	claims := handling.MustGetClaims(c)

	// 读取待绑定记录并核对 QQ
	pending, err := authsvc.GetPendingQQBind(c.Request.Context(), claims.UserID)
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

	// 限制单个 QQ 的拉取频率，防止频繁查询 NapCat
	if err := authsvc.TryAcquireQQRateLimit(c.Request.Context(), pending.QQ); err != nil {
		return err
	}

	pullCtx, cancel := context.WithTimeout(c.Request.Context(), authsvc.QQPullTimeout)
	defer cancel()

	messages, e := qqsvc.GetFriendMsgHistory(pullCtx, pending.QQ, 20)
	if e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to pull QQ messages from NapCat").
			AppendDetails("NapCat 错误")
	}

	// 只在待绑定有效期内、且文本与验证码完全一致的消息中匹配
	cutoff := time.Now().Add(-authsvc.PendingBindDuration).Unix()
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

	// 未匹配到验证码时累计失败次数
	if !matched {
		if err := recordBindFailure(c.Request.Context(), bindQQAttemptsKind, claims.UserID); err != nil {
			return err
		}
		return errs.ForbiddenError().
			AppendDetails("未识别到验证码，请使用该 QQ 向机器人发送验证码")
	}

	// 匹配成功：写入 QQ（旧记录软删除）并清理待绑定状态与失败计数
	if err := usersvc.SetUserQQ(c.Request.Context(), db.R, &model.UserQQ{
		UserID: claims.UserID,
		QQ:     pending.QQ,
	}); err != nil {
		return err
	}

	authsvc.DeletePendingQQBind(c.Request.Context(), claims.UserID)
	authsvc.ResetBindAttempts(c.Request.Context(), bindQQAttemptsKind, claims.UserID)

	handling.RespondOK(c)
	return nil
}

// qqUnbindHandler 解绑当前用户的 QQ：QQ 记录软删除，保留历史。
func qqUnbindHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)
	current, err := usersvc.GetUserQQ(c.Request.Context(), claims.UserID)
	if err != nil {
		return err
	} else if current == nil {
		return errs.NotFoundError().AppendDetails("未绑定 QQ")
	}

	if err := usersvc.DeleteUserQQ(c.Request.Context(), claims.UserID); err != nil {
		return err
	}

	handling.RespondOK(c)
	return nil
}

// checkBindAttempts 检查绑定验证码错误次数是否已达上限；kind 为绑定方式，见包级常量。
// 注意：失败计数在首次失败时设置 PendingBindDuration 过期，到期自动清零。
func checkBindAttempts(ctx context.Context, kind string, userID int64) *errs.Error {
	attempts, err := authsvc.GetBindAttempts(ctx, kind, userID)
	if err != nil {
		return err
	}
	if attempts >= authsvc.MaxBindAttempts {
		return errs.RateLimitExceededError().
			AppendDetails("验证码错误次数过多，请重新发起绑定")
	}
	return nil
}

// recordBindFailure 记录一次绑定验证码错误，达到上限后由 checkBindAttempts 拦截。
func recordBindFailure(ctx context.Context, kind string, userID int64) *errs.Error {
	if _, err := authsvc.IncreaseBindAttempts(ctx, kind, userID); err != nil {
		return err
	}
	return nil
}
