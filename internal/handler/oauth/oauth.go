// Package oauth 提供 OAuth 授权服务器的 HTTP 接口：
// 授权确认、令牌发放、设备授权与用户授权管理。
// 所有接口都使用 JSON 与统一的 errs.Error 错误格式，不要求 OAuth 协议参数。
package oauth

import (
	"fdfz-student-id/internal/middleware"
	"fdfz-student-id/internal/util/handling"

	"github.com/gin-gonic/gin"
)

// InitRoutes 在 /api/v1/oauth 下注册授权相关接口。
func InitRoutes(api *gin.RouterGroup) {
	group := api.Group("/oauth")

	// 授权确认：必须由用户本人操作，OAuth 令牌与提权令牌一律拒绝。
	group.GET("/authorize", middleware.RequireUserToken(), handling.Wrap("授权请求校验失败", authorizePreviewHandler))
	group.POST("/authorize", middleware.RequireUserToken(), handling.Wrap("授权失败", authorizeDecisionHandler))

	// 令牌发放：code 换令牌、刷新令牌、设备轮询与吊销。
	group.POST("/token", handling.Wrap("令牌交换失败", tokenHandler))
	group.POST("/token/refresh", handling.Wrap("令牌刷新失败", refreshHandler))
	group.POST("/token/device", handling.Wrap("设备令牌获取失败", deviceTokenHandler))
	group.POST("/token/revoke", handling.Wrap("令牌吊销失败", revokeHandler))

	// 设备授权：客户端创建设备码，用户在浏览器查看并确认。
	group.POST("/device", handling.Wrap("设备授权请求创建失败", deviceCreateHandler))
	group.GET("/device", middleware.RequireUserToken(), handling.Wrap("设备授权请求获取失败", devicePreviewHandler))
	group.POST("/device/approve", middleware.RequireUserToken(), handling.Wrap("设备授权确认失败", deviceApproveHandler))
}
