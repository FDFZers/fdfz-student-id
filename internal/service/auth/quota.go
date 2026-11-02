package auth

import (
	"context"
	"fmt"
	"time"

	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"

	"github.com/redis/go-redis/v9"
)

var acquireFixedWindowScript = redis.NewScript(`
local n = redis.call('INCR', KEYS[1])
if redis.call('TTL', KEYS[1]) < 0 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return n
`)

// 尽力而为
const (
	RegisterIPQuotaLimit       = 10
	EmailBindUserQuotaLimit    = 10
	EmailBindGlobalQuotaLimit  = 500
	registerIPQuotaWindow      = time.Hour
	emailBindUserQuotaWindow   = 24 * time.Hour
	emailBindGlobalQuotaWindow = 24 * time.Hour
)

func quotaHourBucket(now time.Time) string {
	return now.UTC().Format("2006010215")
}

func quotaDayBucket(now time.Time) string {
	return now.UTC().Format("20060102")
}

func registerIPQuotaCacheKey(ip string, now time.Time) string {
	return fmt.Sprintf("student_id:auth:quota:register:ip:%s:%s", ip, quotaHourBucket(now))
}

func emailBindUserQuotaCacheKey(userID int64, now time.Time) string {
	return fmt.Sprintf("student_id:auth:quota:email_bind:user:%d:%s", userID, quotaDayBucket(now))
}

func emailBindGlobalQuotaCacheKey(now time.Time) string {
	return fmt.Sprintf("student_id:auth:quota:email_bind:global:%s", quotaDayBucket(now))
}

func acquireFixedWindow(
	ctx context.Context,
	key string,
	limit int64,
	window time.Duration,
) (bool, *errs.Error) {
	windowSeconds := int64(window / time.Second)
	if windowSeconds <= 0 {
		windowSeconds = 1
	}
	n, err := acquireFixedWindowScript.Run(ctx, db.R, []string{key}, windowSeconds).Int64()
	if err != nil {
		return false, errs.CreateAndLogInternalError(err, "Failed to increase quota counter").
			AppendDetails("Redis 错误", "频率限制查询失败")
	}
	if n > limit {
		return false, nil
	}
	return true, nil
}

func TryAcquireRegisterIPQuota(ctx context.Context, ip string) *errs.Error {
	ok, err := acquireFixedWindow(
		ctx,
		registerIPQuotaCacheKey(ip, time.Now()),
		RegisterIPQuotaLimit,
		registerIPQuotaWindow,
	)
	if err != nil {
		return err.AppendDetails("注册频率限制查询失败")
	}
	if !ok {
		return errs.RateLimitExceededError().AppendDetails("注册请求过于频繁，请稍后再试")
	}
	return nil
}

func TryAcquireEmailBindQuota(ctx context.Context, userID int64) *errs.Error {
	now := time.Now()
	ok, err := acquireFixedWindow(
		ctx,
		emailBindUserQuotaCacheKey(userID, now),
		EmailBindUserQuotaLimit,
		emailBindUserQuotaWindow,
	)
	if err != nil {
		return err.AppendDetails("邮箱绑定频率限制查询失败")
	}
	if !ok {
		return errs.RateLimitExceededError().AppendDetails("邮箱绑定验证码发送次数过多，请稍后再试")
	}

	ok, err = acquireFixedWindow(
		ctx,
		emailBindGlobalQuotaCacheKey(now),
		EmailBindGlobalQuotaLimit,
		emailBindGlobalQuotaWindow,
	)
	if err != nil {
		return err.AppendDetails("邮箱绑定频率限制查询失败")
	}
	if !ok {
		return errs.RateLimitExceededError().AppendDetails("邮箱绑定验证码发送次数已达全站上限，请稍后再试")
	}
	return nil
}
