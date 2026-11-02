package router

import (
	"fdfz-student-id/internal/cfg"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/handler/auth"
	"fdfz-student-id/internal/handler/healthcheck"
	"fdfz-student-id/internal/handler/misc"
	"fdfz-student-id/internal/handler/regreq"
	"fdfz-student-id/internal/handler/security"
	"fdfz-student-id/internal/handler/user"
	"fdfz-student-id/internal/middleware"
	"fdfz-student-id/internal/model"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func under(path, prefix string) bool {
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}

func InitRouter(r *gin.Engine) {
	apiCors := cors.New(cors.Config{
		AllowAllOrigins: true,
		AllowMethods:    []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:    []string{"Origin", "Content-Type", "Authorization"},
		MaxAge:          12 * time.Hour,
	})
	internalCors := cors.New(cors.Config{
		AllowOriginFunc: func(origin string) bool {
			if origin == "https://fdfz.top" {
				return true
			}
			if !cfg.IsProd && strings.HasSuffix(origin, "localhost") {
				return true
			}
			return strings.HasPrefix(origin, "https://") && strings.HasSuffix(origin, ".fdfz.top")
		},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	})

	r.Use(func(c *gin.Context) {
		switch {
		case under(c.Request.URL.Path, "/api/internal"):
			internalCors(c)
		case under(c.Request.URL.Path, "/api/v1"):
			apiCors(c)
		}
	})

	v1 := r.Group("/api/v1", middleware.ParseToken())
	internal := r.Group("/api/internal", middleware.ParseToken(), func(c *gin.Context) {
		claims, ok := c.Get("claims")
		if !ok {
			return
		}
		typ := claims.(model.RegisteredTokenClaims).TokenType
		if typ != model.TokenTypeUser && typ != model.TokenTypeStepup {
			errs.InvalidTokenError().AppendDetails("令牌类型错误", "鉴权失败").Abort(c)
			return
		}
	})

	misc.InitRoutes(v1, internal)
	auth.InitRoutes(v1, internal)
	regreq.InitRoutes(v1, internal)
	user.InitRoutes(v1, internal)
	security.InitRoutes(internal)
}

func InitHealthCheckRouter(r *gin.Engine) {
	healthcheck.RegisterHealthCheckRoutes(r)
}
