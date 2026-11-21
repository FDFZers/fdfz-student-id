//go:generate go tool go-enum --names --values --marshal --sql
package auth

import (
	"context"
	"fdfz-student-id/internal/cfg"
	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
	usersvc "fdfz-student-id/internal/service/user"
	"fdfz-student-id/internal/util/crypto"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/guregu/null/v6"
	"github.com/redis/go-redis/v9"
)

const (
	// AuthSessionCacheDuration 鉴权会话在 Redis 中的默认存活时间（未下发验证码时）。
	AuthSessionCacheDuration = 2 * time.Minute
	// AuthSession2FACacheDuration 已下发二次验证码的鉴权会话存活时间，与验证码有效期一致。
	AuthSession2FACacheDuration = 10 * time.Minute
	// QQPullRateLimit 同一 QQ 号拉取验证码的最小间隔。
	QQPullRateLimit = 4 * time.Second
	// QQPullTimeout 单次拉取 NapCat 好友消息等 QQ 相关请求的超时时间。
	QQPullTimeout = 3 * time.Second
	// MaxAuthSessionAttempts 单个鉴权会话允许的二次验证失败次数上限。
	MaxAuthSessionAttempts = 5
)

// AuthSessionType 是鉴权会话的类型：login（登录）、stepup（提权）、reset_password（密码重置）。
//
// ENUM(login, stepup, reset_password)
type AuthSessionType string

// AuthSession 是暂存在 Redis 中的鉴权会话，记录本次认证可用的二次验证方式与校验进度。
// 会话本身不落库，过期由 Redis TTL 清理；验证通过后由处理器创建 user_sessions 记录。
type AuthSession struct {
	ID          uuid.UUID       // 会话 ID，仅用于关联二次验证请求
	Type        AuthSessionType // 会话类型，决定验证码邮件文案与可用验证方式
	UserID      int64           // 所属用户；密码重置的匿名会话为 0
	IsTemporary bool            // 是否临时登录会话（仅在 login 类型中有效）
	QQ          null.String     // 已绑定的 QQ 号，无效表示不支持 QQ 验证
	QQCode      null.String     // 待用户发送给机器人的 QQ 验证码
	Email       null.String     // 已绑定的邮箱，无效表示不支持邮箱验证
	EmailCode   null.String     // 已发送的邮箱验证码
	TOTPSecret  null.String     // 已绑定的 TOTP 密钥，无效表示不支持 TOTP 验证
	Passed2FA   bool            // 二次验证是否已通过；没有任何可用验证方式时创建即为 true
}

// AuthSessionIDCacheKey 返回存储鉴权会话的 Redis 键。
func AuthSessionIDCacheKey(id uuid.UUID) string {
	return fmt.Sprintf("student_id:auth:session:info:%s", id)
}

// EmailRateLimitCacheKey 返回邮箱验证码发送冷却的 Redis 键（邮箱统一转小写并去空格）。
func EmailRateLimitCacheKey(email string) string {
	return fmt.Sprintf("student_id:auth:rate_limit:email:%s", strings.ToLower(strings.TrimSpace(email)))
}

// QQRateLimitCacheKey 返回 QQ 消息拉取冷却的 Redis 键。
func QQRateLimitCacheKey(qq string) string {
	return fmt.Sprintf("student_id:auth:rate_limit:qq:%s", qq)
}

// AuthSessionAttemptsCacheKey 返回鉴权会话二次验证失败计数的 Redis 键。
func AuthSessionAttemptsCacheKey(id uuid.UUID) string {
	return fmt.Sprintf("student_id:auth:session:attempts:%s", id)
}

// ValidateUserPassword 校验用户密码。用户不存在与密码错误都返回「用户名或密码错误」，避免暴露账号是否存在。
// 注意：用户不存在或密码记录缺失时也会执行一次 Argon2id 校验，拉平响应耗时防止账号枚举。
func ValidateUserPassword(ctx context.Context, userID int64, password string) *errs.Error {
	pwd, err := usersvc.GetUserPassword(ctx, userID)
	if err != nil {
		return err.AppendDetails("密码验证失败")
	}
	if pwd == nil {
		crypto.BurnPasswordVerifyCost()
		return errs.ForbiddenError().AppendDetails("用户名或密码错误")
	}
	if ok, e := crypto.VerifyArgon2ID(password, pwd.Password); e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to verify user password").AppendDetails("密码验证失败")
	} else if !ok {
		return errs.ForbiddenError().AppendDetails("用户名或密码错误")
	}
	return nil
}

// TryAcquireEmailRateLimit 用 SetNX 占用邮箱验证码发送冷却窗口，同一邮箱在 CodeSendInterval 内只能发一次。
func TryAcquireEmailRateLimit(ctx context.Context, email string) *errs.Error {
	ok, err := db.R.SetNX(ctx, EmailRateLimitCacheKey(email), true, cfg.C.CodeSendInterval).Result()
	if err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to acquire email rate limit").AppendDetails("Redis 错误", "邮箱发送频率限制查询失败")
	} else if !ok {
		return errs.RateLimitExceededError().AppendDetails("邮箱发送频率过快")
	}
	return nil
}

// TryAcquireQQRateLimit 用 SetNX 占用 QQ 消息拉取冷却窗口，同一 QQ 号在 QQPullRateLimit 内只能查询一次。
func TryAcquireQQRateLimit(ctx context.Context, qq string) *errs.Error {
	ok, err := db.R.SetNX(ctx, QQRateLimitCacheKey(qq), true, QQPullRateLimit).Result()
	if err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to acquire QQ rate limit").AppendDetails("Redis 错误", "QQ 接收频率限制查询失败")
	} else if !ok {
		return errs.RateLimitExceededError().AppendDetails("QQ 接收频率过快")
	}
	return nil
}

// CreateAuthSession 按登录上下文创建鉴权会话并写入 Redis，返回会话与可用的二次验证方式。
// 登录类型在校园 IP 内或用户关闭「登录二次验证」时免二次验证；提权类型强制启用全部已绑定方式；
// 密码重置类型只用邮箱与 QQ。注意：没有任何可用验证方式时 Passed2FA 直接为 true。
// twoFactorEnabled 为用户设置中的登录二次验证开关，仅在 login 类型生效。
func CreateAuthSession(ctx context.Context, typ AuthSessionType, isSchoolIp bool, userID int64, isTemporary bool, twoFactorEnabled bool) (*AuthSession, *errs.Error) {
	id := uuid.New()

	var useQQ, useEmail, useTOTP bool
	switch typ {
	case AuthSessionTypeLogin:
		use2FA := !isSchoolIp && twoFactorEnabled
		useQQ, useEmail, useTOTP = use2FA, use2FA, use2FA
	case AuthSessionTypeStepup:
		useQQ, useEmail, useTOTP = true, true, true
	case AuthSessionTypeResetPassword:
		useEmail, useQQ = true, true
	}

	var qq, email, totp null.String
	if useQQ {
		if qqInfo, err := usersvc.GetUserQQ(ctx, userID); err != nil {
			return nil, err
		} else if qqInfo != nil {
			qq = null.StringFrom(qqInfo.QQ)
		}
	}
	if useEmail {
		if emailInfo, err := usersvc.GetUserEmail(ctx, userID); err != nil {
			return nil, err
		} else if emailInfo != nil {
			email = null.StringFrom(emailInfo.Email)
		}
	}
	if useTOTP {
		if totpInfo, err := usersvc.GetUserTOTP(ctx, userID); err != nil {
			return nil, err
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
		return nil, errs.CreateAndLogInternalError(err, "Failed to set auth session").AppendDetails("Redis 错误")
	}
	return session, nil
}

// GetAuthSessionByID 从 Redis 读取鉴权会话。
// 注意：会话不存在时返回 (nil, nil)，调用方需自行判断空值。
func GetAuthSessionByID(ctx context.Context, id uuid.UUID) (*AuthSession, *errs.Error) {
	if res, err := db.GetRedis[AuthSession](ctx, AuthSessionIDCacheKey(id)); err != nil {
		return nil, err
	} else {
		return res, nil
	}
}

// UpdateAuthSession 覆盖写入 Redis 中的鉴权会话。
// codeSent 为 true 时按验证码有效期延长缓存，否则只保留默认的短缓存时间。
func UpdateAuthSession(ctx context.Context, session *AuthSession, codeSent bool) *errs.Error {
	dur := AuthSessionCacheDuration
	if codeSent {
		dur = AuthSession2FACacheDuration
	}
	if err := db.SetRedis(ctx, AuthSessionIDCacheKey(session.ID), session, dur); err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to set auth session").AppendDetails("Redis 错误")
	}
	return nil
}

// DeleteAuthSession 删除 Redis 中的鉴权会话（验证完成或重置密码后清理）。
func DeleteAuthSession(ctx context.Context, session *AuthSession) *errs.Error {
	if err := db.R.Del(ctx, AuthSessionIDCacheKey(session.ID)).Err(); err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to delete auth session").AppendDetails("Redis 错误")
	}
	return nil
}

// INCR 与 EXPIRE 必须在同一脚本中执行，否则 EXPIRE 失败会留下永不过期的计数器。
var consumeAuthSessionAttemptScript = redis.NewScript(`
local n = redis.call('INCR', KEYS[1])
if n == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return n
`)

// ConsumeAuthSessionAttempt 每次验证码输入的二次验证都须先调用计数，无论校验成功失败。
// 注意：QQ 验证为服务端拉取消息的轮询接口，不消耗尝试次数，因此不调用本函数。
func ConsumeAuthSessionAttempt(ctx context.Context, id uuid.UUID) (int64, *errs.Error) {
	ttlSeconds := int64(AuthSession2FACacheDuration / time.Second)
	n, err := consumeAuthSessionAttemptScript.Run(ctx, db.R, []string{AuthSessionAttemptsCacheKey(id)}, ttlSeconds).Int64()
	if err != nil {
		return 0, errs.CreateAndLogInternalError(err, "Failed to consume auth session attempt").AppendDetails("Redis 错误")
	}
	return n, nil
}

// ResetAuthSessionAttempts 清空二次验证失败计数（验证通过后调用）。
func ResetAuthSessionAttempts(ctx context.Context, id uuid.UUID) *errs.Error {
	if err := db.R.Del(ctx, AuthSessionAttemptsCacheKey(id)).Err(); err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to reset auth session attempts").AppendDetails("Redis 错误")
	}
	return nil
}
