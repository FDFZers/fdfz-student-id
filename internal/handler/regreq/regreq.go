package regreq

import (
	"fdfz-student-id/internal/middleware"

	"github.com/gin-gonic/gin"
)

func InitRoutes(api, internal *gin.RouterGroup) {
	a := api.Group("/register_request")
	i := internal.Group("/register_request")

	a.GET("/status", registerRequestStatusHandler)
	i.GET("/detail/:id", middleware.RequireToken(), getRegisterRequestHandler)
	i.GET("/detail/:id/proof_image", middleware.RequireToken(), getRegisterRequestProofImageHandler)
	i.POST("/review", middleware.RequireToken(), reviewRegisterHandler)
	i.GET("/search/info", middleware.RequireToken(), SearchInfoHandler)
	i.POST("/search/query", middleware.RequireToken(), SearchQueryHandler)
}
