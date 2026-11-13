package healthcheck

import (
	"context"
	"fdfz-student-id/internal/db"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// HealthStatus 是 /healthz 的响应体。
type HealthStatus struct {
	Status    string           `json:"status"`           // 整体状态：UP / DOWN（DEGRADED 预留未使用）
	Timestamp string           `json:"timestamp"`        // 检查时间，UTC RFC3339
	Checks    map[string]Check `json:"checks,omitempty"` // 各依赖的检查明细
}

// Check 是单个依赖的检查结果。
type Check struct {
	Status   string `json:"status"`             // UP 或 DOWN
	Message  string `json:"message,omitempty"`  // 失败原因（依赖返回的错误信息）
	Duration string `json:"duration,omitempty"` // 本次检查耗时
}

// timeout 是单次健康检查的总超时时间。
var timeout = 2 * time.Second

// check 并发检查 PostgreSQL 与 Redis，任一依赖 DOWN 则整体状态为 DOWN。
// 注意：所有检查共享同一个 2 秒超时，慢依赖会拖到该上限。
func check(ctx context.Context) HealthStatus {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	result := HealthStatus{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Checks:    make(map[string]Check),
	}

	var mu sync.Mutex
	var wg sync.WaitGroup

	allUp := true

	repo := db.R

	// PostgreSQL
	wg.Go(func() {
		start := time.Now()
		check := Check{}

		if repo == nil || repo.PDB == nil {
			check = Check{Status: "DOWN", Message: "postgres connection is nil"}
		} else {
			err := repo.PDB.Ping(ctx)
			dur := time.Since(start)
			check.Duration = dur.String()
			if err != nil {
				check.Status = "DOWN"
				check.Message = err.Error()
			} else {
				check.Status = "UP"
			}
		}

		mu.Lock()
		result.Checks["postgres"] = check
		if check.Status != "UP" {
			allUp = false
		}
		mu.Unlock()
	})

	// Redis
	wg.Go(func() {
		start := time.Now()
		check := Check{}

		if repo == nil || repo.RDB == nil {
			check = Check{Status: "DOWN", Message: "redis client is nil"}
		} else {
			err := repo.RDB.Ping(ctx).Err()
			dur := time.Since(start)
			check.Duration = dur.String()
			if err != nil {
				check.Status = "DOWN"
				check.Message = err.Error()
			} else {
				check.Status = "UP"
			}
		}

		mu.Lock()
		result.Checks["redis"] = check
		if check.Status != "UP" {
			allUp = false
		}
		mu.Unlock()
	})

	wg.Wait()

	if allUp {
		result.Status = "UP"
	} else {
		result.Status = "DOWN"
	}

	return result
}

// RegisterHealthCheckRoutes 注册存活探针 /ping 与健康检查 /healthz。
// /healthz 在任一依赖 DOWN 时返回 503，供负载均衡与 K8s 探针判断是否摘流量。
func RegisterHealthCheckRoutes(r *gin.Engine) {
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{})
	})

	r.GET("/healthz", func(c *gin.Context) {
		status := check(c.Request.Context())

		code := http.StatusOK
		if status.Status != "UP" {
			code = http.StatusServiceUnavailable
		}

		c.JSON(code, status)
	})
}
