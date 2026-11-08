// Command server 是 FDFZ Student ID 后端的入口：加载配置、初始化数据库/缓存与权限目录、
// 启动 HTTP 服务与定时任务，并在收到退出信号时优雅关闭。
package main

import (
	"context"
	"errors"
	"fdfz-student-id/internal/cfg"
	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/router"
	"fdfz-student-id/internal/service/perm"
	"fdfz-student-id/internal/service/schedule"
	"fdfz-student-id/internal/util/crypto"
	"fdfz-student-id/internal/util/storage"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/lmittmann/tint"
	sloggin "github.com/samber/slog-gin"
)

func main() {
	// 初始化日志：生产环境输出 JSON，开发环境输出带颜色的可读文本。
	var logger *slog.Logger

	if cfg.IsProd {
		logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))
		gin.SetMode(gin.ReleaseMode)
	} else {
		logger = slog.New(tint.NewTextHandler(os.Stdout, &tint.Options{
			Level:      slog.LevelDebug,
			TimeFormat: "2006-01-02 15:04:05",
			NoColor:    false,
		}))
	}

	slog.SetDefault(logger)

	slog.Info("Starting Student ID backend", "commit", cfg.Commit, "build_time", cfg.BuildTime, "is_prod", cfg.IsProd)

	// 读取 .env：仅开发环境生效；生产环境由容器注入环境变量。
	// 注意：cfg.IsProd 在包初始化时读取 APP_ENV，此时 .env 尚未加载，因此 .env 里的 APP_ENV 不生效。
	if !cfg.IsProd {
		if e := godotenv.Load(); e != nil {
			slog.Warn("Error loading .env file", "error", e)
		}
	}

	// 加载环境变量配置（必填项缺失会直接退出）。
	if e := cfg.LoadConfig(); e != nil {
		slog.Error("Error loading config", "error", e)
		os.Exit(1)
	}

	// 初始化本地存储目录（依赖 SHARED_DIR）。
	if e := storage.EnsureDir(); e != nil {
		slog.Error("Error initializing storage directory", "error", e)
		os.Exit(1)
	}

	// 加载 JWT RSA 密钥（从 SHARED_DIR/certs/jwt 读取，并生成 JWKS）。
	if e := crypto.LoadJWTKeys(); e != nil {
		slog.Error("Error initializing jwt keys", "error", e)
		os.Exit(1)
	}

	// 初始化数据库连接。
	pdb, e := db.NewDB()
	if e != nil {
		slog.Error("Error initializing PostgreSQL database", "error", e)
		os.Exit(1)
	}
	slog.Info("PostgreSQL database initialized")

	rdb, e := db.NewRDB()
	if e != nil {
		slog.Error("Error initializing Redis database", "error", e)
		os.Exit(1)
	}
	slog.Info("Redis database initialized")

	db.R = &db.Repo{
		PDB: pdb,
		RDB: rdb,
	}

	// 运行数据库迁移（golang-migrate，内嵌在 db 包中）。
	if e := db.RunMigrations(); e != nil {
		slog.Error("Error running database migrations", "error", e)
		os.Exit(1)
	}
	slog.Info("Database migrations completed")

	// 加载权限目录（同时记录重载状态），并启动后台自动重载。
	if err := perm.ReloadNow(context.Background()); err != nil {
		slog.Error("Error loading permission catalog", "error", err.Info.Error)
		os.Exit(1)
	}
	permCtx, stopPermReload := context.WithCancel(context.Background())
	defer stopPermReload()
	perm.StartAutoReload(permCtx, perm.DefaultReloadThrottle)

	// 启动定时任务（过期会话/封禁清理、账号注销到期处理）。
	cron, e := schedule.ScheduleCron()
	if e != nil {
		slog.Error("Error starting cron", "error", e)
		os.Exit(1)
	}

	// 主服务与健康检查服务分开监听：前者对外，后者仅供容器探针使用。
	r, healthcheckR := gin.New(), gin.New()
	r.Use(sloggin.New(logger))
	r.Use(gin.Recovery())
	healthcheckR.Use(gin.Recovery())

	// 配置可信代理，保证 ClientIP 能正确识别真实客户端（校园网 IP 判定依赖它）。
	if proxies := cfg.C.TrustedProxies; len(proxies) > 0 {
		if e := r.SetTrustedProxies(proxies); e != nil {
			slog.Error("Error setting trusted proxies", "error", e)
		}
	} else {
		if e := r.SetTrustedProxies(nil); e != nil {
			slog.Error("Error setting trusted proxies", "error", e)
		}
	}

	_ = healthcheckR.SetTrustedProxies(nil)

	router.InitRouter(r)
	router.InitHealthCheckRouter(healthcheckR)

	srv := &http.Server{
		Addr:    ":11400",
		Handler: r,
	}

	healthcheckSrv := &http.Server{
		Addr:    ":8080",
		Handler: healthcheckR,
	}

	go func() {
		slog.Info("Starting cron")
		cron.Start()
	}()

	go func() {
		slog.Info("Starting server on port 11400")
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("Server startup failed", "error", err)
			os.Exit(1)
		}
	}()

	// 健康检查端口仅在生产环境开启（本地开发直接跑主服务即可）。
	if cfg.IsProd {
		go func() {
			slog.Info("Starting healthcheck server on port 8080")
			if err := healthcheckSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				slog.Error("Healthcheck server startup failed", "error", err)
			}
		}()
	}

	// 等待退出信号，然后按顺序停止后台任务、关闭服务与连接池。
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("Student ID backend shutting down")

	stopPermReload()

	cron.Stop()
	slog.Info("Cron stopped")

	slog.Info("Waiting for active connections to close")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if e := srv.Shutdown(ctx); e != nil {
		slog.Error("Error shutting down server", "error", e)
	}
	slog.Info("Server shutdown completed")

	if e := healthcheckSrv.Shutdown(ctx); e != nil {
		slog.Error("Error shutting down healthcheck server", "error", e)
	}
	slog.Info("Healthcheck server shutdown completed")

	pdb.Close()
	slog.Info("PostgreSQL database connection pool closed")

	if e := rdb.Close(); e != nil {
		slog.Error("Error closing Redis connection pool", "error", e)
	}
	slog.Info("Redis database connection pool closed")

	slog.Info("Server exited gracefully")
}
