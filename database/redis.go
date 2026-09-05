package database

import (
	"context"
	"fmt"
	"os"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

const RedisEmptyMark = `<{NULL}>`

type RDB struct {
	*goredis.Client
}

func NewRDB() (*RDB, error) {
	// 从环境变量获取 URL
	url := os.Getenv("REDIS_URL")
	if url == "" {
		return nil, fmt.Errorf("redis: environment variable REDIS_URL is not set")
	}

	opts, err := goredis.ParseURL(url)
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

	client := goredis.NewClient(opts)

	// 验证连通性
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("redis: failed to ping: %w", err)
	}

	return &RDB{Client: client}, nil
}
