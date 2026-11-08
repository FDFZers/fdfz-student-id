package auth

import (
	"context"
	"fmt"
	"time"

	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
)

const (
	// PendingBindDuration 待确认的邮箱/TOTP/QQ 绑定请求在 Redis 中的存活时间。
	PendingBindDuration = 10 * time.Minute
	// MaxBindAttempts 单个绑定请求允许的验证码错误次数上限。
	MaxBindAttempts = 5
)

// PendingEmailBindCacheKey 返回待确认邮箱绑定的 Redis 键。
func PendingEmailBindCacheKey(userID int64) string {
	return fmt.Sprintf("student_id:auth:bind:email:%d", userID)
}

// PendingTOTPBindCacheKey 返回待确认 TOTP 绑定的 Redis 键。
func PendingTOTPBindCacheKey(userID int64) string {
	return fmt.Sprintf("student_id:auth:bind:totp:%d", userID)
}

// ---------------------------------------------------------------------------
// 待绑定的邮箱
// ---------------------------------------------------------------------------

// PendingEmailBind 是暂存在 Redis 中的待确认邮箱绑定请求。
type PendingEmailBind struct {
	Email string `json:"email"` // 待绑定的邮箱
	Code  string `json:"code"`  // 已发送到该邮箱的验证码
}

// SetPendingEmailBind 保存待确认的邮箱绑定请求，覆盖该用户此前的请求。
func SetPendingEmailBind(ctx context.Context, userID int64, email, code string) *errs.Error {
	pending := &PendingEmailBind{Email: email, Code: code}
	if err := db.SetRedis(ctx, PendingEmailBindCacheKey(userID), pending, PendingBindDuration); err != nil {
		return err
	}
	return nil
}

// GetPendingEmailBind 读取待确认的邮箱绑定请求，不存在时返回 (nil, nil)。
func GetPendingEmailBind(ctx context.Context, userID int64) (*PendingEmailBind, *errs.Error) {
	pending, err := db.GetRedis[PendingEmailBind](ctx, PendingEmailBindCacheKey(userID))
	if err != nil {
		return nil, err
	}
	return pending, nil
}

// DeletePendingEmailBind 删除待确认的邮箱绑定请求，错误忽略（用于清理，不影响主流程）。
func DeletePendingEmailBind(ctx context.Context, userID int64) {
	db.R.Del(ctx, PendingEmailBindCacheKey(userID))
}

// ---------------------------------------------------------------------------
// 待绑定的 TOTP
// ---------------------------------------------------------------------------

// PendingTOTPBind 是暂存在 Redis 中的待确认 TOTP 绑定请求。
type PendingTOTPBind struct {
	Secret string `json:"secret"` // 待确认的 TOTP 密钥
}

// SetPendingTOTPBind 保存待确认的 TOTP 绑定请求，覆盖该用户此前的请求。
func SetPendingTOTPBind(ctx context.Context, userID int64, secret string) *errs.Error {
	pending := &PendingTOTPBind{Secret: secret}
	if err := db.SetRedis(ctx, PendingTOTPBindCacheKey(userID), pending, PendingBindDuration); err != nil {
		return err
	}
	return nil
}

// GetPendingTOTPBind 读取待确认的 TOTP 绑定请求，不存在时返回 (nil, nil)。
func GetPendingTOTPBind(ctx context.Context, userID int64) (*PendingTOTPBind, *errs.Error) {
	pending, err := db.GetRedis[PendingTOTPBind](ctx, PendingTOTPBindCacheKey(userID))
	if err != nil {
		return nil, err
	}
	return pending, nil
}

// DeletePendingTOTPBind 删除待确认的 TOTP 绑定请求，错误忽略。
func DeletePendingTOTPBind(ctx context.Context, userID int64) {
	db.R.Del(ctx, PendingTOTPBindCacheKey(userID))
}

// ---------------------------------------------------------------------------
// 待绑定的 QQ
// ---------------------------------------------------------------------------

// PendingQQBindCacheKey 返回待确认 QQ 绑定的 Redis 键。
func PendingQQBindCacheKey(userID int64) string {
	return fmt.Sprintf("student_id:auth:bind:qq:%d", userID)
}

// PendingQQBind 是暂存在 Redis 中的待确认 QQ 绑定请求。
type PendingQQBind struct {
	QQ   string `json:"qq"`   // 待绑定的 QQ 号
	Code string `json:"code"` // 要求用户私聊机器人发送的验证码
}

// SetPendingQQBind 保存待确认的 QQ 绑定请求，覆盖该用户此前的请求。
func SetPendingQQBind(ctx context.Context, userID int64, qq, code string) *errs.Error {
	pending := &PendingQQBind{QQ: qq, Code: code}
	if err := db.SetRedis(ctx, PendingQQBindCacheKey(userID), pending, PendingBindDuration); err != nil {
		return err
	}
	return nil
}

// GetPendingQQBind 读取待确认的 QQ 绑定请求，不存在时返回 (nil, nil)。
func GetPendingQQBind(ctx context.Context, userID int64) (*PendingQQBind, *errs.Error) {
	pending, err := db.GetRedis[PendingQQBind](ctx, PendingQQBindCacheKey(userID))
	if err != nil {
		return nil, err
	}
	return pending, nil
}

// DeletePendingQQBind 删除待确认的 QQ 绑定请求，错误忽略。
func DeletePendingQQBind(ctx context.Context, userID int64) {
	db.R.Del(ctx, PendingQQBindCacheKey(userID))
}

// ---------------------------------------------------------------------------
// 绑定验证码错误次数限制
// ---------------------------------------------------------------------------

// bindAttemptsCacheKey 返回按绑定方式与用户隔离的验证码错误计数 Redis 键。
func bindAttemptsCacheKey(kind string, userID int64) string {
	return fmt.Sprintf("student_id:auth:bind:attempts:%s:%d", kind, userID)
}

// GetBindAttempts 读取指定绑定方式的验证码错误次数，未记录时返回 0。
func GetBindAttempts(ctx context.Context, kind string, userID int64) (int64, *errs.Error) {
	n, err := db.GetRedis[int64](ctx, bindAttemptsCacheKey(kind, userID))
	if err != nil {
		return 0, err
	}
	if n == nil {
		return 0, nil
	}
	return *n, nil
}

// IncreaseBindAttempts 原子自增验证码错误次数，首次写入时设置绑定请求的存活时间。
// 注意：过期时间设置失败时会删除计数键，避免留下永不过期的计数器。
func IncreaseBindAttempts(ctx context.Context, kind string, userID int64) (int64, *errs.Error) {
	key := bindAttemptsCacheKey(kind, userID)
	n, err := db.R.Incr(ctx, key).Result()
	if err != nil {
		return 0, errs.CreateAndLogInternalError(err, "Failed to increase bind attempts").
			AppendDetails("Redis 错误")
	}
	if n == 1 {
		if err := db.R.Expire(ctx, key, PendingBindDuration).Err(); err != nil {
			db.R.Del(ctx, key)
			return 0, errs.CreateAndLogInternalError(err, "Failed to set bind attempts expiration").
				AppendDetails("Redis 错误")
		}
	}
	return n, nil
}

// ResetBindAttempts 清空指定绑定方式的验证码错误次数（绑定成功后调用）。
func ResetBindAttempts(ctx context.Context, kind string, userID int64) {
	db.R.Del(ctx, bindAttemptsCacheKey(kind, userID))
}
