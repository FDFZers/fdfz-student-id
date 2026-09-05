package router

import (
	"fdfz-student-id/database"
	"fdfz-student-id/handler/healthcheck"
	"fdfz-student-id/handler/misc"

	"github.com/gin-gonic/gin"
)

func InitRouter(r *gin.Engine, db *database.DB) {
	v1 := r.Group("/api/v1")
	misc.InitRoutes(v1, db)
}

func InitHealthCheckRouter(r *gin.Engine, db *database.DB) {
	healthcheck.RegisterHealthCheckRoutes(r, db)
}
