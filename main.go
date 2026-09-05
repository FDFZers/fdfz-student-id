package main

import (
	"context"
	"errors"
	"fdfz-student-id/database"
	"fdfz-student-id/router"
	"fdfz-student-id/version"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/lmittmann/tint"
	sloggin "github.com/samber/slog-gin"
)

func main() {
	// 初始化环境
	version.IsProd = os.Getenv("APP_ENV") == "prod"

	// 初始化日志记录器
	var logger *slog.Logger

	if version.IsProd {
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

	slog.Info("Starting auth backend", "version", version.Version, "commit", version.Commit, "build_time", version.BuildTime, "is_prod", version.IsProd)

	// 读取 .env
	if !version.IsProd {
		if err := godotenv.Load(); err != nil {
			slog.Warn("Error loading .env file", "error", err)
		}
	}

	// 初始化数据库
	pdb, err := database.NewDB()
	if err != nil {
		slog.Error("Error initializing PostgreSQL database", "error", err)
		os.Exit(1)
	}
	slog.Info("PostgreSQL database initialized")

	rdb, err := database.NewRDB()
	if err != nil {
		slog.Error("Error initializing Redis database", "error", err)
		os.Exit(1)
	}
	slog.Info("Redis database initialized")

	db := &database.DB{
		PDB: pdb,
		RDB: rdb,
	}

	// 运行数据库迁移
	if err := database.RunMigrations(); err != nil {
		slog.Error("Error running database migrations", "error", err)
		os.Exit(1)
	}
	slog.Info("Database migrations completed")

	// 启动服务器
	r, healthcheckR := gin.New(), gin.New()
	r.Use(sloggin.New(logger))
	healthcheckR.Use(sloggin.New(logger))

	if proxy := os.Getenv("TRUSTED_PROXIES"); proxy != "" {
		proxies := strings.Split(proxy, ",")
		for i, p := range proxies {
			proxies[i] = strings.TrimSpace(p)
		}
		if err := r.SetTrustedProxies(proxies); err != nil {
			slog.Error("Error setting trusted proxies", "error", err)
		}
	} else {
		if err := r.SetTrustedProxies(nil); err != nil {
			slog.Error("Error setting trusted proxies", "error", err)
		}
	}

	_ = healthcheckR.SetTrustedProxies(nil)

	router.InitRouter(r, db)
	router.InitHealthCheckRouter(healthcheckR, db)

	srv := &http.Server{
		Addr:    ":11400",
		Handler: r,
	}

	healthcheckSrv := &http.Server{
		Addr:    ":8080",
		Handler: healthcheckR,
	}

	go func() {
		slog.Info("Starting server on port 11400")
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("Server startup failed", "error", err)
			os.Exit(1)
		}
	}()

	if version.IsProd {
		go func() {
			slog.Info("Starting healthcheck server on port 8080")
			if err := healthcheckSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				slog.Error("Healthcheck server startup failed", "error", err)
			}
		}()
	}

	// 优雅关闭服务器
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("Auth backend shutting down")

	slog.Info("Waiting for active connections to close")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("Error shutting down server", "error", err)
	}
	slog.Info("Server shutdown completed")

	if err := healthcheckSrv.Shutdown(ctx); err != nil {
		slog.Error("Error shutting down healthcheck server", "error", err)
	}
	slog.Info("Healthcheck server shutdown completed")

	if err := pdb.Close(); err != nil {
		slog.Error("Error closing PostgreSQL connection pool", "error", err)
	}
	slog.Info("PostgreSQL database connection pool closed")

	if err := rdb.Close(); err != nil {
		slog.Error("Error closing Redis connection pool", "error", err)
	}
	slog.Info("Redis database connection pool closed")

	slog.Info("Server exited gracefully")
}
