package regreq

import (
	"fdfz-student-id/internal/middleware"

	"github.com/gin-gonic/gin"
)

func InitRoutes(api *gin.RouterGroup) {
	group := api.Group("/register_request")
	group.POST("/approve", middleware.ParseToken(), middleware.RequireToken(), middleware.LimitSize(5<<20), setBannerHandler)
	group.GET("/search/info", middleware.ParseToken(), middleware.RequireToken(), SearchInfoHandler)
	group.POST("/search/query", middleware.ParseToken(), middleware.RequireToken(), SearchQueryHandler)
}
