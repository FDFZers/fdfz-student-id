package db

import (
	"context"
	"fdfz-student-id/internal/cfg"
	"fmt"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisEmptyMark 是缓存空值的占位标记，用于区分「未缓存」与「缓存了空结果」，避免缓存穿透。
// 注意：该标记不是合法 JSON，不能与实际序列化数据混淆。
const RedisEmptyMark = `<{NULL}>`

// RDB 包装 go-redis 客户端，供服务层通过 db.R 访问。
type RDB struct {
	*redis.Client
}

// NewRDB 解析 REDIS_URL 并创建客户端，启动时做一次 5 秒超时的连通性检查。
// 注意：Ping 失败会关闭客户端并返回错误，调用方不应继续使用该 Client。
func NewRDB() (*RDB, error) {
	// 从环境变量获取 URL
	url := cfg.C.RedisURL
	if url == "" {
		return nil, fmt.Errorf("redis: environment variable REDIS_URL is not set")
	}

	opts, err := redis.ParseURL(url)
	if err != nil {
		return nil, fmt.Errorf("redis: failed to parse URL: %w", err)
	}

	// 配置连接池
	opts.PoolSize = 20
	opts.MinIdleConns = 5
	opts.MaxIdleConns = 10
	opts.ConnMaxIdleTime = 1 * time.Minute
	opts.ReadTimeout = 3 * time.Second
	opts.WriteTimeout = 3 * time.Second
	opts.DialTimeout = 5 * time.Second

	client := redis.NewClient(opts)

	// 验证连通性
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		if err := client.Close(); err != nil {
			slog.Warn("Failed to close Redis client ping connection", "error", err)
		}
		return nil, fmt.Errorf("redis: failed to ping: %w", err)
	}

	return &RDB{Client: client}, nil
}
