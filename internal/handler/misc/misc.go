package misc

import (
	"fdfz-student-id/internal/cfg"
	"net/http"

	"github.com/gin-gonic/gin"
)

func InitRoutes(api, internal *gin.RouterGroup) {
	api.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "欢迎来到 FDFZ Student ID，远道而来的旅行者！",
		})
	})

	internal.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "你来这里做什么？！",
		})
	})

	api.GET("/version", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"commit":     cfg.Commit,
			"build_time": cfg.BuildTime,
			"is_prod":    cfg.IsProd,
		})
	})

	api.GET("/ipinfo", func(c *gin.Context) {
		ip := c.ClientIP()
		school, ok := cfg.C.SchoolIPs[ip]
		if ok {
			c.JSON(http.StatusOK, gin.H{
				"ip":   ip,
				"type": school,
			})
		} else {
			c.JSON(http.StatusOK, gin.H{
				"ip":   ip,
				"type": "other",
			})
		}
	})
}
