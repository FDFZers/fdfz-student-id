// Package regreq 实现注册申请（register_requests）的查询、搜索与审核 HTTP 处理器。
//
// 注册申请的创建在 auth 包（POST /api/internal/auth/register），本包只负责审核侧接口；
// 端点级失败文案由路由上的 handling.Wrap 追加，处理器内部只追加具体原因。
package regreq

import (
	"fdfz-student-id/internal/middleware"
	"fdfz-student-id/internal/util/handling"

	"github.com/gin-gonic/gin"
)

// InitRoutes 注册注册申请相关路由：status 为无需登录的公开查询，其余均在 internal 组。
func InitRoutes(api, internal *gin.RouterGroup) {
	a := api.Group("/register_request")
	i := internal.Group("/register_request")

	a.GET("/status", handling.Wrap("注册请求状态查询失败", registerRequestStatusHandler))
	i.GET("/detail/:id", middleware.RequireToken(), handling.Wrap("注册请求获取失败", getRegisterRequestHandler))
	i.GET("/detail/:id/proof_image", middleware.RequireToken(), handling.Wrap("佐证图片获取失败", getRegisterRequestProofImageHandler))
	i.POST("/review", middleware.RequireToken(), handling.Wrap("注册请求审核失败", reviewRegisterHandler))
	i.GET("/search/info", middleware.RequireToken(), handling.Wrap("注册请求搜索失败", SearchInfoHandler))
	i.POST("/search/query", middleware.RequireToken(), handling.Wrap("注册请求搜索失败", SearchQueryHandler))
}
