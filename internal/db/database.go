// Package db 提供 PostgreSQL / Redis 连接、数据库迁移与 Redis 缓存读写辅助。
package db

import (
	"context"
	"encoding/json"
	"errors"
	"fdfz-student-id/internal/errs"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"
)

// Repo 聚合 PostgreSQL 与 Redis 连接，进程内统一通过包级变量 R 访问。
type Repo struct {
	*PDB
	*RDB
}

// R 是全局数据库仓库单例，由 cmd/server 在启动阶段初始化。
// 注意：R 必须先于 HTTP 服务与定时任务初始化，否则使用处会空指针。
var R *Repo

// GetRedisFound 读取并反序列化 Redis 缓存，额外返回是否命中缓存。
// 命中空值标记时返回 (nil, true, nil)，用于区分「未缓存」与「缓存了空结果」。
// 注意：缓存数据损坏时直接返回错误，不回源查询。
func GetRedisFound[T any](
	ctx context.Context,
	key string,
) (*T, bool, *errs.Error) {
	// 获取 Redis 缓存值
	res, err := R.Get(ctx, key).Result()
	if err == nil {
		// 命中空值标记
		if res == RedisEmptyMark {
			return nil, true, nil
		}
		// 命中数据
		var data T
		if err := json.Unmarshal([]byte(res), &data); err == nil {
			return &data, true, nil
		} else {
			// 缓存数据损坏，返回解析错误
			return nil, false, errs.CreateAndLogInternalError(err, "Failed to parse cached data").AppendDetails("Redis 缓存数据损坏")
		}
	} else if !errors.Is(err, redis.Nil) {
		// Redis 错误
		return nil, false, errs.CreateAndLogInternalError(err, "Failed to get cached data").AppendDetails("Redis 错误")
	}
	// 缓存未命中
	return nil, false, nil
}

// GetRedis 读取并反序列化 Redis 缓存，未命中时返回 (nil, nil)。
// 需要区分「未缓存」与「缓存空值」时改用 GetRedisFound。
func GetRedis[T any](
	ctx context.Context,
	key string,
) (*T, *errs.Error) {
	data, _, err := GetRedisFound[T](ctx, key)
	return data, err
}

// SetRedis 序列化 value 并以 duration 为有效期写入 Redis。
func SetRedis[T any](
	ctx context.Context,
	key string,
	value T,
	duration time.Duration,
) *errs.Error {
	// 序列化数据
	bytes, err := json.Marshal(&value)
	if err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to marshal cached data").AppendDetails("Redis 数据序列化失败")
	}
	// 设置 Redis 缓存值
	if err := R.Set(ctx, key, bytes, duration).Err(); err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to set cached data").AppendDetails("Redis 缓存值设置失败")
	}
	return nil
}

// GetCached 按「读缓存 — 回源 — 回填缓存」的旁路模式查询数据。
// queryFn 返回 (nil, nil) 表示源数据不存在，此时写入空值标记 RedisEmptyMark 防止缓存穿透。
// 注意：缓存写入失败被有意忽略，不影响本次读取结果。
func GetCached[T any](
	ctx context.Context,
	item, key string,
	duration time.Duration,
	queryFn func() (*T, error), // 缓存未命中时的回源查询函数
) (*T, *errs.Error) {
	rData, found, err := GetRedisFound[T](ctx, key)
	if err != nil {
		return nil, err
	} else if found {
		return rData, nil
	}

	// 数据为空，回源查询
	data, e := queryFn()
	if e == nil {
		// 查询成功，缓存数据，无论是否成功
		if data == nil {
			R.Set(ctx, key, RedisEmptyMark, duration)
			return nil, nil
		}
		SetRedis(ctx, key, data, duration)
		return data, nil
	} else if !errors.Is(e, pgx.ErrNoRows) {
		// 数据库错误
		return nil, errs.CreatePGError(e, item, "Failed to query database")
	}

	// 数据库无数据，缓存空值标记，无论是否成功
	R.Set(ctx, key, RedisEmptyMark, duration)
	return nil, nil
}
