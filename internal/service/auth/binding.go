package auth

import (
	"context"
	"fmt"
	"time"

	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
)

const (
	PendingBindDuration = 10 * time.Minute
	MaxBindAttempts     = 5
)

func PendingEmailBindCacheKey(userID int64) string {
	return fmt.Sprintf("student_id:auth:bind:email:%d", userID)
}

func PendingTOTPBindCacheKey(userID int64) string {
	return fmt.Sprintf("student_id:auth:bind:totp:%d", userID)
}

// ---------------------------------------------------------------------------
// 待绑定的邮箱
// ---------------------------------------------------------------------------

type PendingEmailBind struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

func SetPendingEmailBind(ctx context.Context, userID int64, email, code string) *errs.Error {
	pending := &PendingEmailBind{Email: email, Code: code}
	if err := db.SetRedis(ctx, PendingEmailBindCacheKey(userID), pending, PendingBindDuration); err != nil {
		return err.AppendDetails("邮箱绑定请求保存失败")
	}
	return nil
}

func GetPendingEmailBind(ctx context.Context, userID int64) (*PendingEmailBind, *errs.Error) {
	pending, err := db.GetRedis[PendingEmailBind](ctx, PendingEmailBindCacheKey(userID))
	if err != nil {
		return nil, err.AppendDetails("邮箱绑定请求获取失败")
	}
	return pending, nil
}

func DeletePendingEmailBind(ctx context.Context, userID int64) {
	db.R.Del(ctx, PendingEmailBindCacheKey(userID))
}

// ---------------------------------------------------------------------------
// 待绑定的 TOTP
// ---------------------------------------------------------------------------

type PendingTOTPBind struct {
	Secret string `json:"secret"`
}

func SetPendingTOTPBind(ctx context.Context, userID int64, secret string) *errs.Error {
	pending := &PendingTOTPBind{Secret: secret}
	if err := db.SetRedis(ctx, PendingTOTPBindCacheKey(userID), pending, PendingBindDuration); err != nil {
		return err.AppendDetails("TOTP 绑定请求保存失败")
	}
	return nil
}

func GetPendingTOTPBind(ctx context.Context, userID int64) (*PendingTOTPBind, *errs.Error) {
	pending, err := db.GetRedis[PendingTOTPBind](ctx, PendingTOTPBindCacheKey(userID))
	if err != nil {
		return nil, err.AppendDetails("TOTP 绑定请求获取失败")
	}
	return pending, nil
}

func DeletePendingTOTPBind(ctx context.Context, userID int64) {
	db.R.Del(ctx, PendingTOTPBindCacheKey(userID))
}

// ---------------------------------------------------------------------------
// 待绑定的 QQ
// ---------------------------------------------------------------------------

func PendingQQBindCacheKey(userID int64) string {
	return fmt.Sprintf("student_id:auth:bind:qq:%d", userID)
}

type PendingQQBind struct {
	QQ   string `json:"qq"`
	Code string `json:"code"`
}

func SetPendingQQBind(ctx context.Context, userID int64, qq, code string) *errs.Error {
	pending := &PendingQQBind{QQ: qq, Code: code}
	if err := db.SetRedis(ctx, PendingQQBindCacheKey(userID), pending, PendingBindDuration); err != nil {
		return err.AppendDetails("QQ 绑定请求保存失败")
	}
	return nil
}

func GetPendingQQBind(ctx context.Context, userID int64) (*PendingQQBind, *errs.Error) {
	pending, err := db.GetRedis[PendingQQBind](ctx, PendingQQBindCacheKey(userID))
	if err != nil {
		return nil, err.AppendDetails("QQ 绑定请求获取失败")
	}
	return pending, nil
}

func DeletePendingQQBind(ctx context.Context, userID int64) {
	db.R.Del(ctx, PendingQQBindCacheKey(userID))
}

// ---------------------------------------------------------------------------
// 绑定验证码错误次数限制
// ---------------------------------------------------------------------------

func bindAttemptsCacheKey(kind string, userID int64) string {
	return fmt.Sprintf("student_id:auth:bind:attempts:%s:%d", kind, userID)
}

func GetBindAttempts(ctx context.Context, kind string, userID int64) (int64, *errs.Error) {
	n, err := db.GetRedis[int64](ctx, bindAttemptsCacheKey(kind, userID))
	if err != nil {
		return 0, err.AppendDetails("绑定尝试次数获取失败")
	}
	if n == nil {
		return 0, nil
	}
	return *n, nil
}

func IncreaseBindAttempts(ctx context.Context, kind string, userID int64) (int64, *errs.Error) {
	key := bindAttemptsCacheKey(kind, userID)
	n, err := db.R.Incr(ctx, key).Result()
	if err != nil {
		return 0, errs.CreateAndLogInternalError(err, "Failed to increase bind attempts").
			AppendDetails("Redis 错误", "绑定失败")
	}
	if n == 1 {
		if err := db.R.Expire(ctx, key, PendingBindDuration).Err(); err != nil {
			db.R.Del(ctx, key)
			return 0, errs.CreateAndLogInternalError(err, "Failed to set bind attempts expiration").
				AppendDetails("Redis 错误", "绑定失败")
		}
	}
	return n, nil
}

func ResetBindAttempts(ctx context.Context, kind string, userID int64) {
	db.R.Del(ctx, bindAttemptsCacheKey(kind, userID))
}
