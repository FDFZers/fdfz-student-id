package auth

import (
	"context"
	"fmt"
	"time"

	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"

	"github.com/redis/go-redis/v9"
)

// acquireFixedWindowScript 原子地自增窗口计数，并在键首次创建时设置过期时间，实现固定窗口限流。
var acquireFixedWindowScript = redis.NewScript(`
local n = redis.call('INCR', KEYS[1])
if redis.call('TTL', KEYS[1]) < 0 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return n
`)

// 以下配额均为尽力而为的反滥用限制：Redis 异常时直接报错，不做降级放行。
const (
	// RegisterIPQuotaLimit 单个 IP 每小时允许提交的注册请求数。
	RegisterIPQuotaLimit = 10
	// EmailBindUserQuotaLimit 单个用户每天允许发送的邮箱绑定验证码数。
	EmailBindUserQuotaLimit = 10
	// EmailBindGlobalQuotaLimit 全站每天允许发送的邮箱绑定验证码总数。
	EmailBindGlobalQuotaLimit = 500
	// registerIPQuotaWindow 注册 IP 配额的窗口长度。
	registerIPQuotaWindow = time.Hour
	// emailBindUserQuotaWindow 用户级邮箱绑定配额的窗口长度。
	emailBindUserQuotaWindow = 24 * time.Hour
	// emailBindGlobalQuotaWindow 全站邮箱绑定配额的窗口长度。
	emailBindGlobalQuotaWindow = 24 * time.Hour
)

// quotaHourBucket 返回配额按小时划分的时间桶（UTC，格式 yyyyMMddHH）。
func quotaHourBucket(now time.Time) string {
	return now.UTC().Format("2006010215")
}

// quotaDayBucket 返回配额按天划分的时间桶（UTC，格式 yyyyMMdd）。
func quotaDayBucket(now time.Time) string {
	return now.UTC().Format("20060102")
}

// registerIPQuotaCacheKey 返回注册 IP 配额的 Redis 键（IP + 小时桶）。
func registerIPQuotaCacheKey(ip string, now time.Time) string {
	return fmt.Sprintf("student_id:auth:quota:register:ip:%s:%s", ip, quotaHourBucket(now))
}

// emailBindUserQuotaCacheKey 返回用户级邮箱绑定配额的 Redis 键（用户 + 天桶）。
func emailBindUserQuotaCacheKey(userID int64, now time.Time) string {
	return fmt.Sprintf("student_id:auth:quota:email_bind:user:%d:%s", userID, quotaDayBucket(now))
}

// emailBindGlobalQuotaCacheKey 返回全站邮箱绑定配额的 Redis 键（天桶）。
func emailBindGlobalQuotaCacheKey(now time.Time) string {
	return fmt.Sprintf("student_id:auth:quota:email_bind:global:%s", quotaDayBucket(now))
}

// acquireFixedWindow 在固定窗口内自增计数，计数未超过 limit 时返回 true 表示放行。
// 注意：窗口由调用方拼进 key 的时间桶决定，是固定窗口而非滚动窗口，窗口交界处可能瞬间放行两倍配额。
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
			AppendDetails("Redis 错误")
	}
	if n > limit {
		return false, nil
	}
	return true, nil
}

// TryAcquireRegisterIPQuota 占用一次单 IP 注册配额，超限返回 rate_limit_exceeded。
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

// TryAcquireEmailBindQuota 同时占用用户级与全站邮箱绑定配额，任一超限返回 rate_limit_exceeded。
// 注意：先占用户级配额，再占全站配额；全站超限时用户级计数已被消耗。
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
