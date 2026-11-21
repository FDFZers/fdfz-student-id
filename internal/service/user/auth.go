package user

import (
	"context"
	"errors"
	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"time"

	"github.com/jackc/pgx/v5"
)

// ---------------------------------------------------------------------------
// 获取密码
// ---------------------------------------------------------------------------

// getUserPasswordSQL 查询用户密码哈希（argon2id）。
const getUserPasswordSQL = `
SELECT user_id, password, updated_at FROM user_passwords WHERE user_id = $1
`

func GetUserPassword(ctx context.Context, userID int64) (*model.UserPassword, *errs.Error) {
	var pwd model.UserPassword
	err := db.R.QueryRow(ctx, getUserPasswordSQL, userID).
		Scan(&pwd.UserID, &pwd.Password, &pwd.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, errs.CreatePGError(err, "密码", "Failed to get user password").AppendDetails("获取密码失败")
	}
	return &pwd, nil
}

// ---------------------------------------------------------------------------
// 密码设置
// ---------------------------------------------------------------------------

// upsertUserPasswordSQL 按 user_id 插入或覆盖密码哈希。
const upsertUserPasswordSQL = `
INSERT INTO user_passwords (user_id, password)
VALUES ($1, $2)
ON CONFLICT (user_id)
DO UPDATE SET password = EXCLUDED.password
RETURNING updated_at
`

// UpsertUserPassword 写入或覆盖用户密码哈希，并回填更新时间；pwd.Password 必须已哈希。
func UpsertUserPassword(ctx context.Context, pwd *model.UserPassword) *errs.Error {
	err := db.R.QueryRow(ctx, upsertUserPasswordSQL,
		pwd.UserID,
		pwd.Password,
	).Scan(&pwd.UpdatedAt)
	if err != nil {
		return errs.CreatePGError(err, "密码", "Failed to upsert user password").AppendDetails("密码设置失败")
	}
	return nil
}

// adminResetUserPasswordSQL 在单条语句中写入新密码并更新重设标记，避免两段写入之间出现不一致。
// target 为空（用户不存在或已注销）时不会写入密码，主 UPDATE 也不会命中，最终返回无行。
const adminResetUserPasswordSQL = `
WITH target AS (
    SELECT id FROM users WHERE id = $1 AND deleted_at IS NULL
),
updated_password AS (
    INSERT INTO user_passwords (user_id, password)
    SELECT id, $2 FROM target
    ON CONFLICT (user_id)
    DO UPDATE SET password = EXCLUDED.password
    RETURNING updated_at
)
UPDATE users
SET password_reset_required = $3
WHERE id IN (SELECT id FROM target)
RETURNING (SELECT updated_at FROM updated_password)
`

// AdminResetUserPassword 管理员重置他人密码：pwdHash 必须已哈希，requireReset 决定用户下次登录是否被提示重设。
// 注意：本函数只改密码与标记，不撤销登录会话；调用方需自行撤销目标用户全部会话与提权令牌。
func AdminResetUserPassword(
	ctx context.Context,
	userID int64,
	pwdHash string,
	requireReset bool,
) *errs.Error {
	var updatedAt time.Time
	err := db.R.QueryRow(ctx, adminResetUserPasswordSQL, userID, pwdHash, requireReset).
		Scan(&updatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errs.NotFoundError().AppendDetails("用户不存在")
		}
		return errs.CreatePGError(err, "密码", "Failed to reset user password").AppendDetails("密码重置失败")
	}

	// 用户行上的 updated_at 已变化，必须让用户信息缓存失效。
	db.R.Del(ctx, UserCacheKey(userID))
	return nil
}

// setPasswordResetRequiredSQL 更新用户的重设密码标记。
const setPasswordResetRequiredSQL = `
UPDATE users
SET password_reset_required = $2
WHERE id = $1 AND deleted_at IS NULL
`

// SetPasswordResetRequired 更新用户的重设密码标记，用于用户改密或自助重置后清除提示。
// 用户不存在或已注销时返回 404。
func SetPasswordResetRequired(ctx context.Context, userID int64, required bool) *errs.Error {
	tag, err := db.R.Exec(ctx, setPasswordResetRequiredSQL, userID, required)
	if err != nil {
		return errs.CreatePGError(err, "用户", "Failed to update password reset required").AppendDetails("密码重设标记更新失败")
	}
	if tag.RowsAffected() == 0 {
		return errs.NotFoundError().AppendDetails("用户不存在")
	}

	db.R.Del(ctx, UserCacheKey(userID))
	return nil
}

// setUserPasswordAndClearResetRequiredSQL 在单条语句中写入新密码并清除重设标记，
// 避免出现密码已更新但仍要求重设（或反之）的中间状态。
// target 为空（用户不存在或已注销）时不会写入密码，主 UPDATE 也不会命中，最终返回无行。
const setUserPasswordAndClearResetRequiredSQL = `
WITH target AS (
    SELECT id FROM users WHERE id = $1 AND deleted_at IS NULL
),
updated_password AS (
    INSERT INTO user_passwords (user_id, password)
    SELECT id, $2 FROM target
    ON CONFLICT (user_id)
    DO UPDATE SET password = EXCLUDED.password
    RETURNING updated_at
)
UPDATE users
SET password_reset_required = FALSE
WHERE id IN (SELECT id FROM target)
RETURNING (SELECT updated_at FROM updated_password)
`

// SetUserPasswordAndClearResetRequired 登录时设置新密码并清除重设标记，写入后失效用户缓存。
// passwordHash 须已哈希；用户不存在或已注销时返回 404。
func SetUserPasswordAndClearResetRequired(ctx context.Context, userID int64, passwordHash string) *errs.Error {
	var updatedAt time.Time
	err := db.R.QueryRow(ctx, setUserPasswordAndClearResetRequiredSQL, userID, passwordHash).Scan(&updatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errs.NotFoundError().AppendDetails("用户不存在")
		}
		return errs.CreatePGError(err, "用户", "Failed to set user password").
			AppendDetails("密码设置失败")
	}

	db.R.Del(ctx, UserCacheKey(userID))
	return nil
}

// ---------------------------------------------------------------------------
// 获取 TOTP
// ---------------------------------------------------------------------------

// getUserTotpSQL 查询用户的 TOTP 密钥。
const getUserTotpSQL = `
SELECT user_id, secret, updated_at FROM user_totp WHERE user_id = $1
`

// GetUserTOTP 查询用户的 TOTP 密钥；未绑定过 TOTP 时返回 nil，不返回错误。
func GetUserTOTP(ctx context.Context, userID int64) (*model.UserTOTP, *errs.Error) {
	var t model.UserTOTP
	err := db.R.QueryRow(ctx, getUserTotpSQL, userID).
		Scan(&t.UserID, &t.Secret, &t.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, errs.CreatePGError(err, "TOTP", "Failed to get user TOTP").AppendDetails("获取 TOTP 失败")
	}
	return &t, nil
}

// ---------------------------------------------------------------------------
// 设置 TOTP
// ---------------------------------------------------------------------------

// upsertUserTotpSQL 按 user_id 插入或覆盖 TOTP 密钥。
const upsertUserTotpSQL = `
INSERT INTO user_totp (user_id, secret)
VALUES ($1, $2)
ON CONFLICT (user_id)
DO UPDATE SET secret = EXCLUDED.secret
RETURNING updated_at
`

// UpsertUserTotp 写入或覆盖用户 TOTP 密钥，并回填更新时间。
func UpsertUserTotp(ctx context.Context, t *model.UserTOTP) *errs.Error {
	err := db.R.Pool.QueryRow(ctx, upsertUserTotpSQL, t.UserID, t.Secret).
		Scan(&t.UpdatedAt)
	if err != nil {
		return errs.CreatePGError(err, "TOTP", "Failed to upsert user TOTP").
			AppendDetails("TOTP 设置失败")
	}
	return nil
}

// ---------------------------------------------------------------------------
// 删除 TOTP
// ---------------------------------------------------------------------------

// deleteUserTotpSQL 删除用户的 TOTP 密钥记录。
const deleteUserTotpSQL = `
DELETE FROM user_totp WHERE user_id = $1
`

// DeleteUserTotp 删除用户 TOTP 密钥；未绑定过 TOTP 时删除 0 行也视为成功（幂等）。
func DeleteUserTotp(ctx context.Context, userID int64) *errs.Error {
	if _, err := db.R.Pool.Exec(ctx, deleteUserTotpSQL, userID); err != nil {
		return errs.CreatePGError(err, "TOTP", "Failed to delete user TOTP").
			AppendDetails("TOTP 删除失败")
	}
	return nil
}

// ---------------------------------------------------------------------------
// 登录二次验证开关
// ---------------------------------------------------------------------------

// setUserTwoFactorEnabledSQL 更新用户的登录二次验证开关；已注销用户不会被命中。
const setUserTwoFactorEnabledSQL = `
UPDATE users
SET two_factor_enabled = $2
WHERE id = $1 AND deleted_at IS NULL
RETURNING two_factor_enabled
`

// SetUserTwoFactorEnabled 更新用户的登录二次验证开关，并失效用户信息缓存。
// 注意：重复写入同一值也视为成功；用户不存在或已注销时返回 404。
func SetUserTwoFactorEnabled(ctx context.Context, userID int64, enabled bool) *errs.Error {
	var current bool
	err := db.R.QueryRow(ctx, setUserTwoFactorEnabledSQL, userID, enabled).Scan(&current)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errs.NotFoundError().AppendDetails("用户不存在")
		}
		return errs.CreatePGError(err, "用户", "Failed to update user two factor setting").
			AppendDetails("二次验证设置失败")
	}

	db.R.Del(ctx, UserCacheKey(userID))
	return nil
}
