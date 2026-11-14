package auth

import (
	"context"
	"errors"
	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
	usersvc "fdfz-student-id/internal/service/user"
	"fmt"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
)

// 登录失败次数限制：账号维度严格，IP 维度只做兜底，因为校园网大量用户共享出口 IP。
const (
	LoginUserFailureLimit = 10
	LoginIPFailureLimit   = 100
	LoginFailureWindow    = 15 * time.Minute
)

// 用户级二次验证失败计数：会话级计数可通过重新登录重置，需要独立累计。
const (
	MaxUser2FAAttempts    = 20
	User2FAAttemptsWindow = time.Hour
)

func loginUserFailureCacheKey(username string) string {
	return fmt.Sprintf("student_id:auth:rate_limit:login:user:%s", usersvc.NormalizeUsername(username))
}

func loginIPFailureCacheKey(ip string) string {
	return fmt.Sprintf("student_id:auth:rate_limit:login:ip:%s", ip)
}

func user2FAAttemptsCacheKey(userID int64) string {
	return fmt.Sprintf("student_id:auth:rate_limit:2fa:user:%d", userID)
}

func loginFailureCount(ctx context.Context, key string) (int64, *errs.Error) {
	n, err := db.R.Get(ctx, key).Int64()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return 0, nil
		}
		return 0, errs.CreateAndLogInternalError(err, "Failed to read login failure counter").AppendDetails("登录频率限制查询失败")
	}
	return n, nil
}

// CheckLoginRateLimit 需在密码校验前调用，超限返回 429。
func CheckLoginRateLimit(ctx context.Context, username, ip string) *errs.Error {
	if n, err := loginFailureCount(ctx, loginUserFailureCacheKey(username)); err != nil {
		return err
	} else if n >= LoginUserFailureLimit {
		return errs.RateLimitExceededError().AppendDetails("登录失败次数过多，请稍后再试")
	}

	if ip != "" {
		if n, err := loginFailureCount(ctx, loginIPFailureCacheKey(ip)); err != nil {
			return err
		} else if n >= LoginIPFailureLimit {
			return errs.RateLimitExceededError().AppendDetails("登录尝试过于频繁，请稍后再试")
		}
	}
	return nil
}

func bumpLoginFailure(ctx context.Context, key string, window time.Duration) *errs.Error {
	seconds := int64(window / time.Second)
	if seconds <= 0 {
		seconds = 1
	}
	if _, err := acquireFixedWindowScript.Run(ctx, db.R, []string{key}, seconds).Int64(); err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to increase login failure counter").AppendDetails("登录频率限制更新失败")
	}
	return nil
}

// RecordLoginFailure 记录一次密码错误；计数失败只记日志，不影响登录响应。
func RecordLoginFailure(ctx context.Context, username, ip string) {
	if err := bumpLoginFailure(ctx, loginUserFailureCacheKey(username), LoginFailureWindow); err != nil {
		slog.Warn("Failed to record login failure for user", "error", err.Info.Error)
	}
	if ip != "" {
		if err := bumpLoginFailure(ctx, loginIPFailureCacheKey(ip), LoginFailureWindow); err != nil {
			slog.Warn("Failed to record login failure for ip", "error", err.Info.Error)
		}
	}
}

// ResetLoginFailures 清除账号维度计数；IP 计数保留窗口，避免用自己的账号清零 IP 维度。
func ResetLoginFailures(ctx context.Context, username string) {
	db.R.Del(ctx, loginUserFailureCacheKey(username))
}

func ConsumeUser2FAAttempts(ctx context.Context, userID int64) (int64, *errs.Error) {
	seconds := int64(User2FAAttemptsWindow / time.Second)
	if seconds <= 0 {
		seconds = 1
	}
	n, err := acquireFixedWindowScript.Run(ctx, db.R, []string{user2FAAttemptsCacheKey(userID)}, seconds).Int64()
	if err != nil {
		return 0, errs.CreateAndLogInternalError(err, "Failed to consume user 2fa attempts").AppendDetails("Redis 错误")
	}
	return n, nil
}

func ResetUser2FAAttempts(ctx context.Context, userID int64) {
	db.R.Del(ctx, user2FAAttemptsCacheKey(userID))
}
