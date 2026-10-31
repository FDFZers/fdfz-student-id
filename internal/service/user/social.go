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
// 获取邮箱
// ---------------------------------------------------------------------------

const getUserEmailSQL = `
SELECT id, user_id, email, created_at, deleted_at
FROM user_emails
WHERE user_id = $1 AND deleted_at IS NULL
`

func GetUserEmail(ctx context.Context, userID int64) (*model.UserEmail, *errs.Error) {
	var e model.UserEmail
	err := db.R.QueryRow(ctx, getUserEmailSQL, userID).
		Scan(&e.ID, &e.UserID, &e.Email, &e.CreatedAt, &e.DeletedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, errs.CreatePGError(err, "邮箱", "Failed to get user email").AppendDetails("邮箱获取失败")
	}
	return &e, nil
}

// ---------------------------------------------------------------------------
// 通过 QQ 获取用户
// ---------------------------------------------------------------------------

const getUserIDByQQSQL = `
SELECT u.id
FROM users u
JOIN user_qqs q ON q.user_id = u.id
WHERE q.qq = $1
  AND q.deleted_at IS NULL
  AND u.deleted_at IS NULL
`

func GetUserByQQ(ctx context.Context, qq string) (*model.User, *errs.Error) {
	var id int64
	err := db.R.QueryRow(ctx, getUserIDByQQSQL, qq).Scan(&id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, errs.CreatePGError(err, "用户", "Failed to get user by QQ").AppendDetails("用户获取失败")
	}
	return GetUserByID(ctx, id)
}

// ---------------------------------------------------------------------------
// 检查邮箱是否已被占用
// ---------------------------------------------------------------------------

const isEmailTakenSQL = `
SELECT EXISTS (
    SELECT 1 FROM user_emails
    WHERE lower(email) = lower($1) AND deleted_at IS NULL
)
`

func IsEmailTaken(ctx context.Context, email string) (bool, *errs.Error) {
	var taken bool
	if err := db.R.QueryRow(ctx, isEmailTakenSQL, email).Scan(&taken); err != nil {
		return false, errs.CreatePGError(err, "邮箱", "Failed to check email existence").AppendDetails("邮箱占用信息查询失败")
	}
	return taken, nil
}

// ---------------------------------------------------------------------------
// 通过邮箱获取用户
// ---------------------------------------------------------------------------

const getUserIDByEmailSQL = `
SELECT u.id
FROM users u
JOIN user_emails e ON e.user_id = u.id
WHERE lower(e.email) = lower($1)
  AND e.deleted_at IS NULL
  AND u.deleted_at IS NULL
`

func GetUserByEmail(ctx context.Context, email string) (*model.User, *errs.Error) {
	var id int64
	err := db.R.QueryRow(ctx, getUserIDByEmailSQL, email).Scan(&id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, errs.CreatePGError(err, "用户", "Failed to get user by email").AppendDetails("用户获取失败")
	}
	return GetUserByID(ctx, id)
}

// ---------------------------------------------------------------------------
// 设置邮箱
// ---------------------------------------------------------------------------

const setUserEmailSQL = `
WITH soft_deleted AS (
    UPDATE user_emails
    SET deleted_at = now()
    WHERE user_id = $1 AND deleted_at IS NULL
)
INSERT INTO user_emails (user_id, email)
VALUES ($1, $2)
RETURNING id, created_at
`

func SetUserEmail(ctx context.Context, e *model.UserEmail) *errs.Error {
	err := db.R.Pool.QueryRow(ctx, setUserEmailSQL, e.UserID, e.Email).
		Scan(&e.ID, &e.CreatedAt)
	if err != nil {
		return errs.CreatePGError(err, "邮箱", "Failed to set user email").
			AppendDetails("邮箱设置失败")
	}
	return nil
}

// ---------------------------------------------------------------------------
// 删除邮箱
// ---------------------------------------------------------------------------

const deleteUserEmailSQL = `
UPDATE user_emails
SET deleted_at = now()
WHERE user_id = $1 AND deleted_at IS NULL
`

func DeleteUserEmail(ctx context.Context, userID int64) *errs.Error {
	if _, err := db.R.Pool.Exec(ctx, deleteUserEmailSQL, userID); err != nil {
		return errs.CreatePGError(err, "邮箱", "Failed to delete user email").
			AppendDetails("邮箱删除失败")
	}
	return nil
}

// ---------------------------------------------------------------------------
// 获取QQ
// ---------------------------------------------------------------------------

const getUserQQSQL = `
SELECT id, user_id, qq, created_at, deleted_at
FROM user_qqs
WHERE user_id = $1 AND deleted_at IS NULL
`

func GetUserQQ(ctx context.Context, userID int64) (*model.UserQQ, *errs.Error) {
	var e model.UserQQ
	err := db.R.QueryRow(ctx, getUserQQSQL, userID).
		Scan(&e.ID, &e.UserID, &e.QQ, &e.CreatedAt, &e.DeletedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, errs.CreatePGError(err, "QQ", "Failed to get user QQ").AppendDetails("QQ 获取失败")
	}
	return &e, nil
}

// ---------------------------------------------------------------------------
// 设置QQ
// ---------------------------------------------------------------------------

const setUserQQSQL = `
WITH soft_deleted AS (
    UPDATE user_qqs
    SET deleted_at = now()
    WHERE user_id = $1 AND deleted_at IS NULL
)
INSERT INTO user_qqs (user_id, qq)
VALUES ($1, $2)
RETURNING id, created_at
`

func SetUserQQ(ctx context.Context, e *model.UserQQ) *errs.Error {
	err := db.R.Pool.QueryRow(ctx, setUserQQSQL, e.UserID, e.QQ).
		Scan(&e.ID, &e.CreatedAt)
	if err != nil {
		return errs.CreatePGError(err, "QQ", "Failed to set user QQ").
			AppendDetails("QQ 设置失败")
	}
	return nil
}

// ---------------------------------------------------------------------------
// 删除QQ
// ---------------------------------------------------------------------------

const deleteUserQQSQL = `
UPDATE user_qqs
SET deleted_at = now()
WHERE user_id = $1 AND deleted_at IS NULL
`

func DeleteUserQQ(ctx context.Context, userID int64) *errs.Error {
	if _, err := db.R.Pool.Exec(ctx, deleteUserQQSQL, userID); err != nil {
		return errs.CreatePGError(err, "QQ", "Failed to delete user QQ").
			AppendDetails("QQ 删除失败")
	}
	return nil
}
