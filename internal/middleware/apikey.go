package middleware

import (
	"crypto/subtle"
	"fdfz-student-id/internal/cfg"
	"fdfz-student-id/internal/errs"

	"github.com/gin-gonic/gin"
)

func RequireAPIKey() gin.HandlerFunc {
	return func(c *gin.Context) {
		key := c.GetHeader("X-API-Key")
		if subtle.ConstantTimeCompare([]byte(key), []byte(cfg.C.APIKey)) != 1 {
			errs.InvalidTokenError().AppendDetails("无效的 API Key").Respond(c)
			c.Abort()
			return
		}
		c.Next()
	}
}
