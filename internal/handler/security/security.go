package security

import (
	"fdfz-student-id/internal/middleware"
	"fdfz-student-id/internal/util/handling"

	"github.com/gin-gonic/gin"
)

const (
	bindEmailAttemptsKind = "email"
	bindTOTPAttemptsKind  = "totp"
	bindQQAttemptsKind    = "qq"
)

func InitRoutes(internal *gin.RouterGroup) {
	group := internal.Group("/user/security")

	group.POST("/email/init", bindingValidateClaims(), handling.Wrap("邮箱绑定失败", emailBindInitHandler))
	group.POST("/email/verify", bindingValidateClaims(), handling.Wrap("邮箱绑定失败", emailBindVerifyHandler))
	group.DELETE("/email", bindingValidateClaims(), handling.Wrap("邮箱解绑失败", emailUnbindHandler))
	group.POST("/totp/init", bindingValidateClaims(), handling.Wrap("TOTP 绑定失败", totpBindInitHandler))
	group.POST("/totp/verify", bindingValidateClaims(), handling.Wrap("TOTP 绑定失败", totpBindVerifyHandler))
	group.DELETE("/totp", bindingValidateClaims(), handling.Wrap("TOTP 解绑失败", totpUnbindHandler))
	group.POST("/qq/init", bindingValidateClaims(), handling.Wrap("QQ 绑定失败", qqBindInitHandler))
	group.POST("/qq/verify", bindingValidateClaims(), handling.Wrap("QQ 绑定失败", qqBindVerifyHandler))
	group.DELETE("/qq", bindingValidateClaims(), handling.Wrap("QQ 解绑失败", qqUnbindHandler))

	group.POST("/password/change", middleware.RequireStepupToken(), handling.Wrap("修改密码失败", changePasswordHandler))
	group.DELETE("/account", middleware.RequireStepupToken(), handling.Wrap("账号注销失败", deleteAccountHandler))

	group.GET("/sessions", middleware.RequireToken(), handling.Wrap("会话列表获取失败", listSessionsHandler))
	group.DELETE("/sessions", middleware.RequireStepupToken(), handling.Wrap("会话撤销失败", revokeAllSessionsHandler))
	group.DELETE("/sessions/:id", middleware.RequireStepupToken(), handling.Wrap("会话撤销失败", revokeSessionHandler))
}
