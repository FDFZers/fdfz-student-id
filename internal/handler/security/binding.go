package security

import (
	"crypto/subtle"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/middleware"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/service/auth"
	"fdfz-student-id/internal/service/email"
	"fdfz-student-id/internal/service/user"
	cryptoutil "fdfz-student-id/internal/util/crypto"
	"fdfz-student-id/internal/util/validation"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type emailBindInitReq struct {
	Email string `json:"email"`
}

func emailBindInitHandler(c *gin.Context) {
	var req emailBindInitReq
	if err := c.ShouldBindJSON(&req); err != nil {
		errs.BadRequestError().AppendDetails("请求解析失败", "邮箱绑定失败").Respond(c)
		return
	}
	if err := validation.ValidateEmail(req.Email); err != nil {
		err.AppendDetails("邮箱绑定失败").Respond(c)
		return
	}

	claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)

	current, err := user.GetUserEmail(c.Request.Context(), claims.UserID)
	if err != nil {
		err.AppendDetails("邮箱绑定失败").Respond(c)
		return
	}
	if current != nil && strings.EqualFold(current.Email, req.Email) {
		errs.ConflictError().AppendDetails("该邮箱已绑定", "邮箱绑定失败").Respond(c)
		return
	}

	taken, err := user.IsEmailTaken(c.Request.Context(), req.Email)
	if err != nil {
		err.AppendDetails("邮箱绑定失败").Respond(c)
		return
	}
	if taken {
		errs.ConflictError().AppendDetails("该邮箱已被其他用户绑定", "邮箱绑定失败").Respond(c)
		return
	}

	if err := auth.ValidateEmailRateLimit(c.Request.Context(), req.Email); err != nil {
		err.AppendDetails("邮箱绑定失败").Respond(c)
		return
	}

	code, error := cryptoutil.GenerateCode(6, cryptoutil.CodeCharset)
	if error != nil {
		errs.CreateAndLogInternalError(error, "Failed to generate email bind code").
			AppendDetails("验证码生成失败", "邮箱绑定失败").Respond(c)
		return
	}

	if err := auth.SetPendingEmailBind(c.Request.Context(), claims.UserID, req.Email, code); err != nil {
		err.AppendDetails("邮箱绑定失败").Respond(c)
		return
	}

	if err := email.SendBindEmailCode(req.Email, code); err != nil {
		auth.DeletePendingEmailBind(c.Request.Context(), claims.UserID)
		errs.CreateAndLogInternalError(err, "Failed to send email bind code").
			AppendDetails("邮件发送失败", "邮箱绑定失败").Respond(c)
		return
	}

	auth.UpdateEmailLastSentAt(c.Request.Context(), req.Email)

	c.JSON(http.StatusOK, gin.H{})
}

type emailBindVerifyReq struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

func emailBindVerifyHandler(c *gin.Context) {
	var req emailBindVerifyReq
	if err := c.ShouldBindJSON(&req); err != nil {
		errs.BadRequestError().AppendDetails("请求解析失败", "邮箱绑定失败").Respond(c)
		return
	}
	if err := validation.ValidateEmail(req.Email); err != nil {
		err.AppendDetails("邮箱绑定失败").Respond(c)
		return
	}
	if req.Code == "" {
		errs.BadRequestError().AppendDetails("验证码不能为空", "邮箱绑定失败").Respond(c)
		return
	}

	claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)

	pending, err := auth.GetPendingEmailBind(c.Request.Context(), claims.UserID)
	if err != nil {
		err.AppendDetails("邮箱绑定失败").Respond(c)
		return
	} else if pending == nil {
		errs.IllegalStateError().AppendDetails("邮箱绑定未发起或已过期", "邮箱绑定失败").Respond(c)
		return
	}
	if !strings.EqualFold(pending.Email, req.Email) {
		errs.BadRequestError().AppendDetails("邮箱与绑定请求不一致", "邮箱绑定失败").Respond(c)
		return
	}

	if !checkBindAttempts(c, bindEmailAttemptsKind, claims.UserID) {
		return
	}

	if subtle.ConstantTimeCompare([]byte(pending.Code), []byte(req.Code)) != 1 {
		if !recordBindFailure(c, bindEmailAttemptsKind, claims.UserID) {
			return
		}
		errs.ForbiddenError().AppendDetails("验证码错误", "邮箱绑定失败").Respond(c)
		return
	}

	if err := user.SetUserEmail(c.Request.Context(), &model.UserEmail{
		UserID: claims.UserID,
		Email:  pending.Email,
	}); err != nil {
		err.AppendDetails("邮箱绑定失败").Respond(c)
		return
	}

	auth.DeletePendingEmailBind(c.Request.Context(), claims.UserID)
	auth.ResetBindAttempts(c.Request.Context(), bindEmailAttemptsKind, claims.UserID)

	c.JSON(http.StatusOK, gin.H{})
}

func emailUnbindHandler(c *gin.Context) {
	claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)
	current, err := user.GetUserEmail(c.Request.Context(), claims.UserID)
	if err != nil {
		err.AppendDetails("邮箱解绑失败").Respond(c)
		return
	} else if current == nil {
		errs.NotFoundError().AppendDetails("未绑定邮箱", "邮箱解绑失败").Respond(c)
		return
	}

	if err := user.DeleteUserEmail(c.Request.Context(), claims.UserID); err != nil {
		err.AppendDetails("邮箱解绑失败").Respond(c)
		return
	}

	c.JSON(http.StatusOK, gin.H{})
}

func totpBindInitHandler(c *gin.Context) {
	claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)
	existing, err := user.GetUserTOTP(c.Request.Context(), claims.UserID)
	if err != nil {
		err.AppendDetails("TOTP 绑定失败").Respond(c)
		return
	} else if existing != nil {
		errs.ConflictError().AppendDetails("已绑定 TOTP", "TOTP 绑定失败").Respond(c)
		return
	}

	secret, otpauthURL, error := cryptoutil.GenerateTOTP(uint64(claims.UserID))
	if error != nil {
		errs.CreateAndLogInternalError(error, "Failed to generate TOTP secret").
			AppendDetails("TOTP 密钥生成失败", "TOTP 绑定失败").Respond(c)
		return
	}

	if err := auth.SetPendingTOTPBind(c.Request.Context(), claims.UserID, secret); err != nil {
		err.AppendDetails("TOTP 绑定失败").Respond(c)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"secret": secret,
		"url":    otpauthURL,
	})
}

type totpBindVerifyReq struct {
	Code string `json:"code"`
}

func totpBindVerifyHandler(c *gin.Context) {
	var req totpBindVerifyReq
	if err := c.ShouldBindJSON(&req); err != nil {
		errs.BadRequestError().AppendDetails("请求解析失败", "TOTP 绑定失败").Respond(c)
		return
	}
	if err := validation.ValidateTOTPCode(req.Code); err != nil {
		err.AppendDetails("TOTP 绑定失败").Respond(c)
		return
	}

	claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)

	pending, err := auth.GetPendingTOTPBind(c.Request.Context(), claims.UserID)
	if err != nil {
		err.AppendDetails("TOTP 绑定失败").Respond(c)
		return
	} else if pending == nil {
		errs.IllegalStateError().AppendDetails("TOTP 绑定未发起或已过期", "TOTP 绑定失败").Respond(c)
		return
	}

	if !checkBindAttempts(c, bindTOTPAttemptsKind, claims.UserID) {
		return
	}

	ok2, error := cryptoutil.VerifyTOTP(pending.Secret, req.Code)
	if error != nil {
		errs.CreateAndLogInternalError(error, "Failed to verify TOTP code").
			AppendDetails("TOTP 校验失败", "TOTP 绑定失败").Respond(c)
		return
	}
	if !ok2 {
		if !recordBindFailure(c, bindTOTPAttemptsKind, claims.UserID) {
			return
		}
		errs.ForbiddenError().AppendDetails("验证码错误", "TOTP 绑定失败").Respond(c)
		return
	}

	if err := user.UpsertUserTotp(c.Request.Context(), &model.UserTOTP{
		UserID: claims.UserID,
		Secret: pending.Secret,
	}); err != nil {
		err.AppendDetails("TOTP 绑定失败").Respond(c)
		return
	}

	auth.DeletePendingTOTPBind(c.Request.Context(), claims.UserID)
	auth.ResetBindAttempts(c.Request.Context(), bindTOTPAttemptsKind, claims.UserID)

	c.JSON(http.StatusOK, gin.H{})
}

func totpUnbindHandler(c *gin.Context) {
	claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)
	existing, err := user.GetUserTOTP(c.Request.Context(), claims.UserID)
	if err != nil {
		err.AppendDetails("TOTP 解绑失败").Respond(c)
		return
	} else if existing == nil {
		errs.NotFoundError().AppendDetails("未绑定 TOTP", "TOTP 解绑失败").Respond(c)
		return
	}

	if err := user.DeleteUserTotp(c.Request.Context(), claims.UserID); err != nil {
		err.AppendDetails("TOTP 解绑失败").Respond(c)
		return
	}

	c.JSON(http.StatusOK, gin.H{})
}

func bindingValidateClaims() gin.HandlerFunc {
	return func(c *gin.Context) {
		middleware.RequireTokenType(model.TokenTypeStepup)(c)
		if c.IsAborted() {
			return
		}

		claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)
		if claims.IsTemporary {
			errs.PermissionDeniedError().AppendDetails("临时会话无法修改安全设置", "鉴权失败").Abort(c)
			return
		}

		ban, err := user.GetUserBan(c.Request.Context(), claims.UserID)
		if err != nil {
			err.AppendDetails("鉴权失败").Abort(c)
			return
		}
		if ban != nil {
			errs.PermissionDeniedError().AppendDetails("用户已被封禁", "鉴权失败").Abort(c)
			return
		}
	}
}

func checkBindAttempts(c *gin.Context, kind string, userID int64) bool {
	attempts, err := auth.GetBindAttempts(c.Request.Context(), kind, userID)
	if err != nil {
		err.AppendDetails("绑定失败").Respond(c)
		return false
	}
	if attempts >= auth.MaxBindAttempts {
		errs.RateLimitExceededError().
			AppendDetails("验证码错误次数过多，请重新发起绑定", "绑定失败").Respond(c)
		return false
	}
	return true
}

func recordBindFailure(c *gin.Context, kind string, userID int64) bool {
	if _, err := auth.IncreaseBindAttempts(c.Request.Context(), kind, userID); err != nil {
		err.AppendDetails("绑定失败").Respond(c)
		return false
	}
	return true
}
