//go:generate go tool go-enum --names --values --marshal --sql
package auth

import (
	"context"
	"fdfz-student-id/internal/cfg"
	"fdfz-student-id/internal/crypto"
	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/service/user"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/guregu/null/v6"
)

const (
	AuthSessionCacheDuration    = 2 * time.Minute
	AuthSession2FACacheDuration = 10 * time.Minute
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
	LastSentAt  time.Time
	Passed2FA   bool
}

func (s *AuthSession) canSendCode() bool {
	return time.Since(s.LastSentAt) > cfg.C.CodeSendInterval
}

func AuthSessionIDCacheKey(id uuid.UUID) string {
	return fmt.Sprintf("student_id:auth:session:info:%s", id)
}

func AuthSessionQQCacheKey(qq string) string {
	return fmt.Sprintf("student_id:auth:session:id_by_qq:%s", qq)
}

func ValidateUserPassword(ctx context.Context, userID int64, password string) *errs.Error {
	pwd, err := user.GetUserPassword(ctx, userID)
	if err != nil {
		return err.AppendDetails("密码验证失败")
	}
	if ok, err := crypto.VerifyUserPassword(password, pwd); err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to verify user password").AppendDetails("密码验证失败")
	} else if !ok {
		return errs.UnauthorizedError().AppendDetails("用户名或密码错误", "密码验证失败")
	}
	if pwd.Algorithm == model.PasswordAlgorithmBcrypt {
		hash, err := crypto.HashArgon2ID(password)
		if err != nil {
			slog.Warn("Failed to hash when migrating password", "error", err, "userID", userID)
		}
		user.UpsertUserPassword(ctx, &model.UserPassword{
			UserID:    userID,
			Password:  hash,
			Algorithm: model.PasswordAlgorithmArgon2ID,
		})
	}
	return nil
}

func CreateAuthSession(ctx context.Context, typ AuthSessionType, isSchoolIp bool, userID int64, isTemporary bool) (*AuthSession, *errs.Error) {
	id := uuid.New()

	var qq, email, totp null.String
	if typ != AuthSessionTypeLogin || !isSchoolIp {
		if qqInfo, err := user.GetUserQQ(ctx, userID); err != nil {
			return nil, err.AppendDetails("鉴权会话创建失败")
		} else if qqInfo != nil {
			qq = null.StringFrom(qqInfo.QQ)
		}
		if emailInfo, err := user.GetUserEmail(ctx, userID); err != nil {
			return nil, err.AppendDetails("鉴权会话创建失败")
		} else if emailInfo != nil {
			email = null.StringFrom(emailInfo.Email)
		}
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
	if qq.Valid {
		if err := db.SetRedis(ctx, AuthSessionQQCacheKey(qq.String), id, AuthSessionCacheDuration); err != nil {
			return nil, errs.CreateAndLogInternalError(err, "Failed to set auth session by QQ").AppendDetails("Redis 错误", "鉴权会话创建失败")
		}
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

func GetAuthSessionByQQ(ctx context.Context, qq string) (*AuthSession, *errs.Error) {
	id, err := db.GetRedis[uuid.UUID](ctx, AuthSessionQQCacheKey(qq))
	if err != nil {
		return nil, err.AppendDetails("鉴权会话获取失败")
	} else if id == nil {
		return nil, errs.NotFoundError().AppendDetails("鉴权会话不存在")
	}
	return GetAuthSessionByID(ctx, *id)
}

func UpdateAuthSession(ctx context.Context, session *AuthSession, codeSent bool) *errs.Error {
	dur := AuthSessionCacheDuration
	if codeSent {
		dur = AuthSession2FACacheDuration
	}
	if err := db.SetRedis(ctx, AuthSessionIDCacheKey(session.ID), session, dur); err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to set auth session").AppendDetails("Redis 错误", "鉴权会话更新失败")
	}
	if session.QQ.Valid {
		if err := db.SetRedis(ctx, AuthSessionQQCacheKey(session.QQ.String), session.ID, dur); err != nil {
			return errs.CreateAndLogInternalError(err, "Failed to set auth session by QQ").AppendDetails("Redis 错误", "鉴权会话更新失败")
		}
	}
	return nil
}

func DeleteAuthSession(ctx context.Context, id uuid.UUID) *errs.Error {
	if err := db.R.Del(ctx, AuthSessionIDCacheKey(id)); err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to delete auth session").AppendDetails("Redis 错误", "鉴权会话删除失败")
	}
	if err := db.R.Del(ctx, AuthSessionQQCacheKey(id.String())); err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to delete auth session by QQ").AppendDetails("Redis 错误", "鉴权会话删除失败")
	}
	return nil
}
