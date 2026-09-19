package user

import (
	"context"
	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
)

// ---------------------------------------------------------------------------
// 密码设置
// ---------------------------------------------------------------------------

const upsertUserPasswordSQL = `
INSERT INTO user_passwords (user_id, password, algorithm)
VALUES ($1, $2, $3)
ON CONFLICT (user_id)
DO UPDATE SET password = EXCLUDED.password, algorithm = EXCLUDED.algorithm
RETURNING updated_at
`

func UpsertUserPassword(ctx context.Context, pwd *model.UserPassword) *errs.Error {
	err := db.R.QueryRow(ctx, upsertUserPasswordSQL,
		pwd.UserID,
		pwd.Password,
		pwd.Algorithm,
	).Scan(&pwd.UpdatedAt)
	if err != nil {
		return errs.CreatePGError(err, "密码", "Failed to upsert user password").AppendDetails("密码设置失败")
	}
	return nil
}

// ---------------------------------------------------------------------------
// 获取 TOTP
// ---------------------------------------------------------------------------

const getUserTotpSQL = `
SELECT user_id, secret, updated_at FROM user_totp WHERE user_id = $1
`

func GetUserTotp(ctx context.Context, userID int64) (*model.UserTotp, *errs.Error) {
	var t model.UserTotp
	err := db.R.QueryRow(ctx, getUserTotpSQL, userID).
		Scan(&t.UserID, &t.Secret, &t.UpdatedAt)
	if err != nil {
		return nil, errs.CreatePGError(err, "TOTP", "Failed to get user TOTP").AppendDetails("获取 TOTP 失败")
	}
	return &t, nil
}

// ---------------------------------------------------------------------------
// 设置 TOTP
// ---------------------------------------------------------------------------

const upsertUserTotpSQL = `
INSERT INTO user_totp (user_id, secret)
VALUES ($1, $2)
ON CONFLICT (user_id)
DO UPDATE SET secret = EXCLUDED.secret
RETURNING updated_at
`

func UpsertUserTotp(ctx context.Context, t *model.UserTotp) *errs.Error {
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

const deleteUserTotpSQL = `
DELETE FROM user_totp WHERE user_id = $1
`

func DeleteUserTotp(ctx context.Context, userID int64) *errs.Error {
	if _, err := db.R.Pool.Exec(ctx, deleteUserTotpSQL, userID); err != nil {
		return errs.CreatePGError(err, "TOTP", "Failed to delete user TOTP").
			AppendDetails("TOTP 删除失败")
	}
	return nil
}
