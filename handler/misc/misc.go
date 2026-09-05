package misc

import (
	"fdfz-student-id/database"
	"fdfz-student-id/version"
	"net/http"

	"github.com/gin-gonic/gin"
)

func InitRoutes(group *gin.RouterGroup, db *database.DB) {
	group.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "欢迎来到 FDFZ Student ID，远道而来的冒险者！",
		})
	})

	group.GET("/version", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"version":    version.Version,
			"commit":     version.Commit,
			"build_time": version.BuildTime,
			"is_prod":    version.IsProd,
		})
	})
}
