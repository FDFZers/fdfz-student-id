// Package misc 提供根路径、版本信息与客户端 IP 归属等杂项接口。
package misc

import (
	"fdfz-student-id/internal/cfg"
	"net/http"

	"github.com/gin-gonic/gin"
)

// InitRoutes 注册杂项路由：根路径问候、版本信息与 IP 归属查询。
// 注意：根路径在对外与内部 API 分组下都注册，/version 与 /ipinfo 仅在对外分组。
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

	// 按 SCHOOL_IPS 映射判断客户端 IP 是否属于校园网，匹配不到时返回 other
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
