package regreq

import (
	"fdfz-student-id/internal/middleware"
	"fdfz-student-id/internal/util/handling"

	"github.com/gin-gonic/gin"
)

func InitRoutes(api, internal *gin.RouterGroup) {
	a := api.Group("/register_request")
	i := internal.Group("/register_request")

	a.GET("/status", handling.Wrap("注册请求状态查询失败", registerRequestStatusHandler))
	i.GET("/detail/:id", middleware.RequireToken(), handling.Wrap("注册申请获取失败", getRegisterRequestHandler))
	i.GET("/detail/:id/proof_image", middleware.RequireToken(), handling.Wrap("佐证图片获取失败", getRegisterRequestProofImageHandler))
	i.POST("/review", middleware.RequireToken(), handling.Wrap("注册请求审核失败", reviewRegisterHandler))
	i.GET("/search/info", middleware.RequireToken(), handling.Wrap("注册请求搜索失败", SearchInfoHandler))
	i.POST("/search/query", middleware.RequireToken(), handling.Wrap("注册请求搜索失败", SearchQueryHandler))
}
