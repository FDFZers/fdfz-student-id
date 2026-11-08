package user

import (
	"context"
	"errors"
	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"

	"github.com/jackc/pgx/v5"
)

// ---------------------------------------------------------------------------
// 获取密码
// ---------------------------------------------------------------------------

// getUserPasswordSQL 查询用户密码哈希（argon2id）。
const getUserPasswordSQL = `
SELECT user_id, password, updated_at FROM user_passwords WHERE user_id = $1
`

// GetUserPassword 查询用户的密码哈希；用户没有密码记录时返回 404。
func GetUserPassword(ctx context.Context, userID int64) (*model.UserPassword, *errs.Error) {
	var pwd model.UserPassword
	err := db.R.QueryRow(ctx, getUserPasswordSQL, userID).
		Scan(&pwd.UserID, &pwd.Password, &pwd.UpdatedAt)
	if err != nil {
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
