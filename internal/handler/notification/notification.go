package notification

import (
	"fdfz-student-id/internal/middleware"
	permsvc "fdfz-student-id/internal/service/perm"
	"fdfz-student-id/internal/util/handling"

	"github.com/gin-gonic/gin"
)

// InitRoutes 注册站内通知与统一通知发送路由：api 组只操作自己的通知，internal 组承载统一发送与全部通知搜索。
func InitRoutes(api, internal *gin.RouterGroup) {
	self := api.Group("/notifications")
	self.GET("", middleware.RequirePermission(permsvc.PermNotificationRead), handling.Wrap("通知列表获取失败", listHandler))
	self.POST("/send", handling.Wrap("通知发送失败", appSendHandler))
	self.GET("/:id", middleware.RequirePermission(permsvc.PermNotificationRead), handling.Wrap("通知获取失败", getHandler))
	self.PUT("/read-all", middleware.RequirePermission(permsvc.PermNotificationWrite), handling.Wrap("通知全部标记已读失败", markAllReadHandler))
	self.PUT("/:id/read", middleware.RequirePermission(permsvc.PermNotificationWrite), handling.Wrap("通知标记已读失败", markReadHandler))
	self.DELETE("/:id", middleware.RequirePermission(permsvc.PermNotificationWrite), handling.Wrap("通知删除失败", deleteHandler))

	internal.POST("/notifications/send", middleware.RequirePermission(permsvc.PermNotificationsSend), handling.Wrap("通知发送失败", sendHandler))
	internal.GET("/notifications/search/info", middleware.RequirePermission(permsvc.PermNotificationsRead), handling.Wrap("通知搜索信息获取失败", notificationSearchInfoHandler))
	internal.POST("/notifications/search/query", middleware.RequirePermission(permsvc.PermNotificationsRead), handling.Wrap("通知搜索失败", notificationSearchQueryHandler))
}
