package security

import (
	"fdfz-student-id/internal/middleware"
	"fdfz-student-id/internal/service/perm"
	"fdfz-student-id/internal/util/handling"

	"github.com/gin-gonic/gin"
)

const (
	bindEmailAttemptsKind = "email"
	bindTOTPAttemptsKind  = "totp"
	bindQQAttemptsKind    = "qq"
)

func InitRoutes(internal *gin.RouterGroup) {
	group := internal.Group("/security")

	group.POST("/email/init", middleware.RequireStepupToken(), handling.Wrap("邮箱绑定失败", emailBindInitHandler))
	group.POST("/email/verify", middleware.RequireStepupToken(), handling.Wrap("邮箱绑定失败", emailBindVerifyHandler))
	group.DELETE("/email", middleware.RequireStepupToken(), handling.Wrap("邮箱解绑失败", emailUnbindHandler))
	group.POST("/totp/init", middleware.RequireStepupToken(), handling.Wrap("TOTP 绑定失败", totpBindInitHandler))
	group.POST("/totp/verify", middleware.RequireStepupToken(), handling.Wrap("TOTP 绑定失败", totpBindVerifyHandler))
	group.DELETE("/totp", middleware.RequireStepupToken(), handling.Wrap("TOTP 解绑失败", totpUnbindHandler))
	group.POST("/qq/init", middleware.RequireStepupToken(), handling.Wrap("QQ 绑定失败", qqBindInitHandler))
	group.POST("/qq/verify", middleware.RequireStepupToken(), handling.Wrap("QQ 绑定失败", qqBindVerifyHandler))
	group.DELETE("/qq", middleware.RequireStepupToken(), handling.Wrap("QQ 解绑失败", qqUnbindHandler))

	group.POST("/password/change", middleware.RequireStepupToken(), handling.Wrap("修改密码失败", changePasswordHandler))
	group.DELETE("/account", middleware.RequireStepupToken(), handling.Wrap("账号注销失败", deleteAccountHandler))

	group.DELETE("/profile/:id", middleware.RequirePermission(perm.PermUsersDelete), handling.Wrap("用户删除失败", deleteUserHandler))

	group.GET("/session", middleware.RequireToken(), handling.Wrap("会话列表获取失败", listSessionsHandler))
	group.DELETE("/session", middleware.RequireStepupToken(), handling.Wrap("会话撤销失败", revokeSessionsHandler))
	group.DELETE("/session/:id", middleware.RequireStepupToken(), handling.Wrap("会话撤销失败", revokeSessionHandler))

	group.GET("/sessions/:userID", middleware.RequireToken(), handling.Wrap("会话列表获取失败", listSessionsHandler))
	group.DELETE("/sessions/:userID", middleware.RequireToken(), handling.Wrap("会话撤销失败", revokeSessionsHandler))
	group.DELETE("/sessions/:userID/:id", middleware.RequireToken(), handling.Wrap("会话撤销失败", revokeSessionHandler))
}
