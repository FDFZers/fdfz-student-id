package router

import (
	"fdfz-student-id/internal/cfg"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/handler/app"
	"fdfz-student-id/internal/handler/auth"
	"fdfz-student-id/internal/handler/healthcheck"
	"fdfz-student-id/internal/handler/misc"
	"fdfz-student-id/internal/handler/notification"
	"fdfz-student-id/internal/handler/oauth"
	"fdfz-student-id/internal/handler/permissions"
	"fdfz-student-id/internal/handler/regreq"
	"fdfz-student-id/internal/handler/security"
	"fdfz-student-id/internal/handler/user"
	"fdfz-student-id/internal/middleware"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/util/handling"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

// under 判断 path 是否等于 prefix 或位于 prefix 的子路径下（用于按前缀套用 CORS）。
func under(path, prefix string) bool {
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}

// InitRouter 初始化 API 路由：/api/v1 为普通接口，/api/internal 为内部管理接口。
func InitRouter(r *gin.Engine) {
	// /api/v1 面向公网前端：允许任意来源，只放行 Bearer 认证（不依赖 Cookie 跨域）。
	apiCors := cors.New(cors.Config{
		AllowAllOrigins: true,
		AllowMethods:    []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:    []string{"Origin", "Content-Type", "Authorization"},
		MaxAge:          12 * time.Hour,
	})
	// /api/internal 面向内部管理前端：只允许 fdfz.top 及其子域，允许携带 Cookie。
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

	// 按路径前缀选择 CORS 策略。
	r.Use(func(c *gin.Context) {
		switch {
		case under(c.Request.URL.Path, "/api/internal"):
			internalCors(c)
		case under(c.Request.URL.Path, "/api/v1"):
			apiCors(c)
		}
	})

	// 两组路由都先解析令牌；internal 组额外限制令牌类型，禁止 OAuth 令牌访问内部接口。
	// 默认请求体上限 1 MiB，上传类路由可用 LimitSize 覆盖。
	v1 := r.Group("/api/v1", middleware.ParseToken(), middleware.DefaultLimitSize())
	internal := r.Group("/api/internal", middleware.ParseToken(), middleware.DefaultLimitSize(), func(c *gin.Context) {
		claims := handling.GetClaimsOrNil(c)
		if claims == nil {
			return
		}
		if claims.TokenType != model.TokenTypeUser && claims.TokenType != model.TokenTypeStepup {
			errs.InvalidTokenError().AppendDetails("令牌类型错误").Abort(c)
			return
		}
	})

	// 各业务模块自行注册路由；路由上的处理函数统一用 handling.Wrap 追加端点级失败文案。
	misc.InitRoutes(v1, internal)
	auth.InitRoutes(v1, internal)
	regreq.InitRoutes(v1, internal)
	user.InitRoutes(v1, internal)
	security.InitRoutes(v1, internal)
	permissions.InitRoutes(internal)
	app.InitRoutes(v1, internal)
	oauth.InitRoutes(v1)
	notification.InitRoutes(v1, internal)
}

// InitHealthCheckRouter 注册健康检查路由（生产环境单独监听 8080 端口）。
func InitHealthCheckRouter(r *gin.Engine) {
	healthcheck.RegisterHealthCheckRoutes(r)
}
