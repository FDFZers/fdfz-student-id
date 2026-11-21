package security

import (
	"fdfz-student-id/internal/middleware"
	permsvc "fdfz-student-id/internal/service/perm"
	"fdfz-student-id/internal/util/handling"

	"github.com/gin-gonic/gin"
)

// 绑定验证码错误次数的 Redis 计数维度，需与 auth 服务中使用的 key 保持一致。
const (
	bindEmailAttemptsKind = "email"
	bindTOTPAttemptsKind  = "totp"
)

// InitRoutes 注册账号安全相关路由。
// api 组为公网 /api/v1，允许用户令牌与已获授权的 OAuth 令牌读取自己的绑定信息；
// internal 组为内部管理接口，承载提权操作、会话管理与他人绑定信息的读写。
// 注意：危险操作要求提权令牌，会话相关接口还叠加了用户组权限校验。
func InitRoutes(api, internal *gin.RouterGroup) {
	self := api.Group("/security")
	group := internal.Group("/security")

	// 绑定信息自助查询：挂在 /api/v1，使用 binding.*（可被 OAuth 应用申请）
	self.GET("/binding/status", middleware.RequirePermission(permsvc.PermBindingReadStatus), handling.Wrap("绑定状态获取失败", getBindingStatusHandler))
	self.GET("/binding/email", middleware.RequirePermission(permsvc.PermBindingReadEmail), handling.Wrap("绑定邮箱获取失败", getBindingEmailHandler))
	self.GET("/binding/qq", middleware.RequirePermission(permsvc.PermBindingReadQQ), handling.Wrap("绑定 QQ 获取失败", getBindingQQHandler))

	// 绑定信息管理：查询他人使用 bindings.read.*，设置或删除使用 bindings.write
	group.GET("/binding/:id/status", middleware.RequirePermission(permsvc.PermBindingsReadStatus), handling.Wrap("绑定状态获取失败", getBindingStatusHandler))
	group.GET("/binding/:id/email", middleware.RequirePermission(permsvc.PermBindingsReadEmail), handling.Wrap("绑定邮箱获取失败", getBindingEmailHandler))
	group.GET("/binding/:id/qq", middleware.RequirePermission(permsvc.PermBindingsReadQQ), handling.Wrap("绑定 QQ 获取失败", getBindingQQHandler))

	// 管理员直接设置或删除他人的绑定，绕过验证码校验
	group.PUT("/binding/:id/email", middleware.RequirePermission(permsvc.PermBindingsWrite), handling.Wrap("绑定邮箱设置失败", setBindingEmailHandler))
	group.DELETE("/binding/:id/email", middleware.RequirePermission(permsvc.PermBindingsWrite), handling.Wrap("绑定邮箱删除失败", deleteBindingEmailHandler))
	group.PUT("/binding/:id/qq", middleware.RequirePermission(permsvc.PermBindingsWrite), handling.Wrap("绑定 QQ 设置失败", setBindingQQHandler))
	group.DELETE("/binding/:id/qq", middleware.RequirePermission(permsvc.PermBindingsWrite), handling.Wrap("绑定 QQ 删除失败", deleteBindingQQHandler))

	// 登录二次验证开关：查询只要求访问令牌，修改要求提权令牌；仅影响登录流程，提权仍强制校验
	group.GET("/2fa", middleware.RequireUserToken(), handling.Wrap("二次验证设置获取失败", getTwoFactorSettingHandler))
	group.PUT("/2fa", middleware.RequireStepupToken(), handling.Wrap("二次验证设置修改失败", updateTwoFactorSettingHandler))

	// 关闭后任何应用都不能再向该用户发送通知
	group.GET("/app-notifications", middleware.RequireUserToken(), handling.Wrap("应用通知设置获取失败", getAppNotificationsSettingHandler))
	group.PUT("/app-notifications", middleware.RequireUserToken(), handling.Wrap("应用通知设置修改失败", updateAppNotificationsSettingHandler))

	// 邮箱、TOTP、QQ 的绑定与解绑
	group.POST("/email/init", middleware.RequireStepupToken(), handling.Wrap("邮箱绑定失败", emailBindInitHandler))
	group.POST("/email/verify", middleware.RequireStepupToken(), handling.Wrap("邮箱绑定失败", emailBindVerifyHandler))
	group.DELETE("/email", middleware.RequireStepupToken(), handling.Wrap("邮箱解绑失败", emailUnbindHandler))
	group.POST("/totp/init", middleware.RequireStepupToken(), handling.Wrap("TOTP 绑定失败", totpBindInitHandler))
	group.POST("/totp/verify", middleware.RequireStepupToken(), handling.Wrap("TOTP 绑定失败", totpBindVerifyHandler))
	group.DELETE("/totp", middleware.RequireStepupToken(), handling.Wrap("TOTP 解绑失败", totpUnbindHandler))
	group.POST("/qq/init", middleware.RequireStepupToken(), handling.Wrap("QQ 绑定失败", qqBindInitHandler))
	group.POST("/qq/verify", middleware.RequireStepupToken(), handling.Wrap("QQ 绑定失败", qqBindVerifyHandler))
	group.DELETE("/qq", middleware.RequireStepupToken(), handling.Wrap("QQ 解绑失败", qqUnbindHandler))

	// 修改密码、注销账号与管理员删除用户
	group.POST("/password/change", middleware.RequireStepupToken(), handling.Wrap("修改密码失败", changePasswordHandler))
	group.PUT("/password/reset/:id", middleware.RequirePermission(permsvc.PermUsersPasswordWrite), handling.Wrap("密码重置失败", resetUserPasswordHandler))
	group.DELETE("/account", middleware.RequireStepupToken(), handling.Wrap("账号注销失败", deleteAccountHandler))
	group.DELETE("/profile/:id", middleware.RequirePermission(permsvc.PermUsersDelete), handling.Wrap("用户删除失败", deleteUserHandler))

	// 会话列表与撤销：会话列表只要求访问令牌，撤销要求提权令牌
	group.GET("/session", middleware.RequireToken(), handling.Wrap("会话列表获取失败", listSessionsHandler))
	group.DELETE("/session", middleware.RequireStepupToken(), handling.Wrap("会话撤销失败", revokeSessionsHandler))
	group.DELETE("/session/:id", middleware.RequireStepupToken(), handling.Wrap("会话撤销失败", revokeSessionHandler))

	group.GET("/sessions/:userID", middleware.RequireToken(), handling.Wrap("会话列表获取失败", listSessionsHandler))
	group.DELETE("/sessions/:userID", middleware.RequireToken(), handling.Wrap("会话撤销失败", revokeSessionsHandler))
	group.DELETE("/sessions/:userID/:id", middleware.RequireToken(), handling.Wrap("会话撤销失败", revokeSessionHandler))
}
