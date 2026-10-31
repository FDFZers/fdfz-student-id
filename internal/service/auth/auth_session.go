//go:generate go tool go-enum --names --values --marshal --sql
package auth

import (
	"context"
	"fdfz-student-id/internal/cfg"
	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/service/user"
	"fdfz-student-id/internal/util/crypto"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/guregu/null/v6"
)

const (
	AuthSessionCacheDuration    = 2 * time.Minute
	AuthSession2FACacheDuration = 10 * time.Minute
	QQPullRateLimit             = 4 * time.Second
	QQPullTimeout               = 3 * time.Second
	MaxAuthSessionAttempts      = 5
)

// ENUM(login, stepup, reset_password)
type AuthSessionType string

type AuthSession struct {
	ID          uuid.UUID
	Type        AuthSessionType
	UserID      int64
	IsTemporary bool // 仅在 login 类型的会话中有效
	QQ          null.String
	QQCode      null.String
	Email       null.String
	EmailCode   null.String
	TOTPSecret  null.String
	Passed2FA   bool
}

func AuthSessionIDCacheKey(id uuid.UUID) string {
	return fmt.Sprintf("student_id:auth:session:info:%s", id)
}

func EmailRateLimitCacheKey(email string) string {
	return fmt.Sprintf("student_id:auth:rate_limit:email:%s", email)
}

func QQRateLimitCacheKey(qq string) string {
	return fmt.Sprintf("student_id:auth:rate_limit:qq:%s", qq)
}

func AuthSessionAttemptsCacheKey(id uuid.UUID) string {
	return fmt.Sprintf("student_id:auth:session:attempts:%s", id)
}

func ValidateUserPassword(ctx context.Context, userID int64, password string) *errs.Error {
	pwd, err := user.GetUserPassword(ctx, userID)
	if err != nil {
		if err.Info.Error == "not_found" {
			return errs.ForbiddenError().AppendDetails("用户名或密码错误", "密码验证失败")
		}
		return err.AppendDetails("密码验证失败")
	}
	if ok, err := crypto.VerifyArgon2ID(password, pwd.Password); err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to verify user password").AppendDetails("密码验证失败")
	} else if !ok {
		return errs.ForbiddenError().AppendDetails("用户名或密码错误", "密码验证失败")
	}
	return nil
}

func TryAcquireEmailRateLimit(ctx context.Context, email string) *errs.Error {
	ok, err := db.R.SetNX(ctx, EmailRateLimitCacheKey(email), true, cfg.C.CodeSendInterval).Result()
	if err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to acquire email rate limit").AppendDetails("Redis 错误", "邮箱发送频率限制查询失败")
	} else if !ok {
		return errs.RateLimitExceededError().AppendDetails("邮箱发送频率过快")
	}
	return nil
}

func TryAcquireQQRateLimit(ctx context.Context, qq string) *errs.Error {
	ok, err := db.R.SetNX(ctx, QQRateLimitCacheKey(qq), true, QQPullRateLimit).Result()
	if err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to acquire QQ rate limit").AppendDetails("Redis 错误", "QQ 接收频率限制查询失败")
	} else if !ok {
		return errs.RateLimitExceededError().AppendDetails("QQ 接收频率过快")
	}
	return nil
}

func CreateAuthSession(ctx context.Context, typ AuthSessionType, isSchoolIp bool, userID int64, isTemporary bool) (*AuthSession, *errs.Error) {
	id := uuid.New()

	var useQQ, useEmail, useTOTP bool
	switch typ {
	case AuthSessionTypeLogin:
		useQQ, useEmail, useTOTP = !isSchoolIp, !isSchoolIp, !isSchoolIp
	case AuthSessionTypeStepup:
		useQQ, useEmail, useTOTP = true, true, true
	case AuthSessionTypeResetPassword:
		useEmail, useQQ = true, true
	}

	var qq, email, totp null.String
	if useQQ {
		if qqInfo, err := user.GetUserQQ(ctx, userID); err != nil {
			return nil, err.AppendDetails("鉴权会话创建失败")
		} else if qqInfo != nil {
			qq = null.StringFrom(qqInfo.QQ)
		}
	}
	if useEmail {
		if emailInfo, err := user.GetUserEmail(ctx, userID); err != nil {
			return nil, err.AppendDetails("鉴权会话创建失败")
		} else if emailInfo != nil {
			email = null.StringFrom(emailInfo.Email)
		}
	}
	if useTOTP {
		if totpInfo, err := user.GetUserTOTP(ctx, userID); err != nil {
			return nil, err.AppendDetails("鉴权会话创建失败")
		} else if totpInfo != nil {
			totp = null.StringFrom(totpInfo.Secret)
		}
	}

	session := &AuthSession{
		ID:          id,
		Type:        typ,
		UserID:      userID,
		IsTemporary: isTemporary,
		QQ:          qq,
		Email:       email,
		TOTPSecret:  totp,
		Passed2FA:   !qq.Valid && !email.Valid && !totp.Valid,
	}

	if err := db.SetRedis(ctx, AuthSessionIDCacheKey(id), session, AuthSessionCacheDuration); err != nil {
		return nil, errs.CreateAndLogInternalError(err, "Failed to set auth session").AppendDetails("Redis 错误", "鉴权会话创建失败")
	}
	return session, nil
}

func GetAuthSessionByID(ctx context.Context, id uuid.UUID) (*AuthSession, *errs.Error) {
	if res, err := db.GetRedis[AuthSession](ctx, AuthSessionIDCacheKey(id)); err != nil {
		return nil, err.AppendDetails("鉴权会话获取失败")
	} else {
		return res, nil
	}
}

func UpdateAuthSession(ctx context.Context, session *AuthSession, codeSent bool) *errs.Error {
	dur := AuthSessionCacheDuration
	if codeSent {
		dur = AuthSession2FACacheDuration
	}
	if err := db.SetRedis(ctx, AuthSessionIDCacheKey(session.ID), session, dur); err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to set auth session").AppendDetails("Redis 错误", "鉴权会话更新失败")
	}
	return nil
}

func DeleteAuthSession(ctx context.Context, session *AuthSession) *errs.Error {
	if err := db.R.Del(ctx, AuthSessionIDCacheKey(session.ID)).Err(); err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to delete auth session").AppendDetails("Redis 错误", "鉴权会话删除失败")
	}
	return nil
}

func GetAuthSessionAttempts(ctx context.Context, id uuid.UUID) (int64, *errs.Error) {
	n, err := db.GetRedis[int64](ctx, AuthSessionAttemptsCacheKey(id))
	if err != nil {
		return 0, errs.CreateAndLogInternalError(err, "Failed to get auth session attempts").AppendDetails("Redis 错误", "二次验证失败")
	} else if n == nil {
		return 0, nil
	}
	return *n, nil
}

func IncreaseAuthSessionAttempts(ctx context.Context, id uuid.UUID) (int64, *errs.Error) {
	key := AuthSessionAttemptsCacheKey(id)
	n, err := db.R.Incr(ctx, key).Result()
	if err != nil {
		return 0, errs.CreateAndLogInternalError(err, "Failed to increase auth session attempts").AppendDetails("Redis 错误", "二次验证失败")
	}
	if n == 1 {
		if err := db.R.Expire(ctx, key, AuthSession2FACacheDuration).Err(); err != nil {
			db.R.Del(ctx, key)
			return 0, errs.CreateAndLogInternalError(err, "Failed to set auth session attempts expiration").AppendDetails("Redis 错误", "二次验证失败")
		}
	}
	return n, nil
}

func ResetAuthSessionAttempts(ctx context.Context, id uuid.UUID) *errs.Error {
	if err := db.R.Del(ctx, AuthSessionAttemptsCacheKey(id)).Err(); err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to reset auth session attempts").AppendDetails("Redis 错误", "二次验证失败")
	}
	return nil
}
