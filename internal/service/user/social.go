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

// getUserEmailSQL 查询用户当前生效的邮箱绑定（每用户最多一条未删除记录）。
const getUserEmailSQL = `
SELECT id, user_id, email, created_at, deleted_at
FROM user_emails
WHERE user_id = $1 AND deleted_at IS NULL
`

// GetUserEmail 查询用户已绑定的邮箱；未绑定时返回 nil，不返回错误。
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

// getUserIDByQQSQL 通过未删除的 QQ 绑定查找对应未删除用户。
const getUserIDByQQSQL = `
SELECT u.id
FROM users u
JOIN user_qqs q ON q.user_id = u.id
WHERE q.qq = $1
  AND q.deleted_at IS NULL
  AND u.deleted_at IS NULL
`

// GetUserByQQ 通过 QQ 号查询绑定的用户；未绑定或用户已删除时返回 nil，不返回错误。
func GetUserByQQ(ctx context.Context, qq string) (*model.User, *errs.Error) {
	var id int64
	err := db.R.QueryRow(ctx, getUserIDByQQSQL, qq).Scan(&id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, errs.CreatePGError(err, "用户", "Failed to get user by QQ")
	}
	return GetUserByID(ctx, id)
}

// ---------------------------------------------------------------------------
// 检查邮箱是否已被占用
// ---------------------------------------------------------------------------

// isEmailTakenSQL 检查邮箱（大小写不敏感）是否已被未删除的绑定占用。
const isEmailTakenSQL = `
SELECT EXISTS (
    SELECT 1 FROM user_emails
    WHERE lower(email) = lower($1) AND deleted_at IS NULL
)
`

// IsEmailTaken 检查邮箱是否已被其他用户绑定；本函数不缓存结果。
func IsEmailTaken(ctx context.Context, email string) (bool, *errs.Error) {
	var taken bool
	if err := db.R.QueryRow(ctx, isEmailTakenSQL, email).Scan(&taken); err != nil {
		return false, errs.CreatePGError(err, "邮箱", "Failed to check email existence").AppendDetails("邮箱占用信息查询失败")
	}
	return taken, nil
}

// ---------------------------------------------------------------------------
// 检查 QQ 是否已被占用
// ---------------------------------------------------------------------------

// isQQTakenSQL 检查 QQ 号是否已被未删除的绑定占用。
const isQQTakenSQL = `
SELECT EXISTS (
    SELECT 1 FROM user_qqs
    WHERE qq = $1 AND deleted_at IS NULL
)
`

// IsQQTaken 检查 QQ 号是否已被其他用户绑定；本函数不缓存结果。
func IsQQTaken(ctx context.Context, qq string) (bool, *errs.Error) {
	var taken bool
	if err := db.R.QueryRow(ctx, isQQTakenSQL, qq).Scan(&taken); err != nil {
		return false, errs.CreatePGError(err, "QQ", "Failed to check QQ existence").AppendDetails("QQ 占用信息查询失败")
	}
	return taken, nil
}

// ---------------------------------------------------------------------------
// 通过邮箱获取用户
// ---------------------------------------------------------------------------

// getUserIDByEmailSQL 通过未删除的邮箱绑定查找对应未删除用户。
const getUserIDByEmailSQL = `
SELECT u.id
FROM users u
JOIN user_emails e ON e.user_id = u.id
WHERE lower(e.email) = lower($1)
  AND e.deleted_at IS NULL
  AND u.deleted_at IS NULL
`

// GetUserByEmail 通过邮箱查询绑定的用户；未绑定或用户已删除时返回 nil，不返回错误。
func GetUserByEmail(ctx context.Context, email string) (*model.User, *errs.Error) {
	var id int64
	err := db.R.QueryRow(ctx, getUserIDByEmailSQL, email).Scan(&id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, errs.CreatePGError(err, "用户", "Failed to get user by email")
	}
	return GetUserByID(ctx, id)
}

// ---------------------------------------------------------------------------
// 设置邮箱
// ---------------------------------------------------------------------------

// setUserEmailSQL 单条语句完成「软删除旧邮箱 + 插入新邮箱」，保证每用户仅一条生效记录。
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

// SetUserEmail 绑定邮箱：软删除该用户原邮箱后插入新记录，并回填 id 与创建时间。
// 注意：唯一索引保证同一邮箱只能被一个用户绑定，冲突时由 CreatePGError 转为 409。
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

// deleteUserEmailSQL 软删除该用户当前生效的邮箱绑定。
const deleteUserEmailSQL = `
UPDATE user_emails
SET deleted_at = now()
WHERE user_id = $1 AND deleted_at IS NULL
`

// DeleteUserEmail 解绑邮箱（软删除）；未绑定时更新 0 行也视为成功（幂等）。
func DeleteUserEmail(ctx context.Context, userID int64) *errs.Error {
	if _, err := db.R.Pool.Exec(ctx, deleteUserEmailSQL, userID); err != nil {
		return errs.CreatePGError(err, "邮箱", "Failed to delete user email").
			AppendDetails("邮箱删除失败")
	}
	return nil
}

// ---------------------------------------------------------------------------
// 获取 QQ
// ---------------------------------------------------------------------------

// getUserQQSQL 查询用户当前生效的 QQ 绑定。
const getUserQQSQL = `
SELECT id, user_id, qq, created_at, deleted_at
FROM user_qqs
WHERE user_id = $1 AND deleted_at IS NULL
`

// GetUserQQ 查询用户已绑定的 QQ 号；未绑定时返回 nil，不返回错误。
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
// 设置 QQ
// ---------------------------------------------------------------------------

// setUserQQSQL 单条语句完成「软删除旧 QQ + 插入新 QQ」，保证每用户仅一条生效记录。
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

// SetUserQQ 绑定 QQ：软删除该用户原 QQ 后插入新记录，并回填 id 与创建时间。
// 注意：唯一索引保证同一 QQ 只能被一个用户绑定，冲突时由 CreatePGError 转为 409。
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
// 删除 QQ
// ---------------------------------------------------------------------------

// deleteUserQQSQL 软删除该用户当前生效的 QQ 绑定。
const deleteUserQQSQL = `
UPDATE user_qqs
SET deleted_at = now()
WHERE user_id = $1 AND deleted_at IS NULL
`

// DeleteUserQQ 解绑 QQ（软删除）；未绑定时更新 0 行也视为成功（幂等）。
func DeleteUserQQ(ctx context.Context, userID int64) *errs.Error {
	if _, err := db.R.Pool.Exec(ctx, deleteUserQQSQL, userID); err != nil {
		return errs.CreatePGError(err, "QQ", "Failed to delete user QQ").
			AppendDetails("QQ 删除失败")
	}
	return nil
}
