package user

import (
	"context"
	"errors"
	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
	"time"

	"github.com/guregu/null/v6"
	"github.com/jackc/pgx/v5"
)

// AccountDeletionDelay 是账号注销的冷静期：申请后 7 天内重新登录可取消，到期由定时任务完成清理。
const AccountDeletionDelay = 7 * 24 * time.Hour

// systemAdminUserID 是用户被删除后其 OAuth 应用的接收者（系统管理员）用户 ID，默认 1。
const systemAdminUserID int64 = 1

// ---------------------------------------------------------------------------
// 申请注销
// ---------------------------------------------------------------------------

// scheduleAccountDeletionSQL 写入注销冷静期截止时间；COALESCE 保证重复申请不会延长已排定的时间。
const scheduleAccountDeletionSQL = `
UPDATE users
SET deletion_scheduled_at = COALESCE(deletion_scheduled_at, now() + make_interval(secs => $2))
WHERE id = $1 AND deleted_at IS NULL
RETURNING deletion_scheduled_at
`

// ScheduleAccountDeletion 为指定用户排定账号注销，返回计划的删除时间。
// 注意：已排定过注销的用户再次申请不会改变原时间；用户不存在时返回 404。
func ScheduleAccountDeletion(
	ctx context.Context,
	userID int64,
	delay time.Duration,
) (time.Time, *errs.Error) {
	var scheduledAt time.Time
	err := db.R.QueryRow(ctx, scheduleAccountDeletionSQL, userID, delay.Seconds()).Scan(&scheduledAt)
	if err != nil {
		return time.Time{}, errs.CreatePGError(err, "用户", "Failed to schedule account deletion")
	}
	return scheduledAt, nil
}

// ---------------------------------------------------------------------------
// 获取注销时间
// ---------------------------------------------------------------------------

// getAccountDeletionScheduledAtSQL 查询用户已排定的注销时间。
const getAccountDeletionScheduledAtSQL = `
SELECT deletion_scheduled_at FROM users WHERE id = $1 AND deleted_at IS NULL
`

// GetAccountDeletionScheduledAt 查询用户排定的注销时间；未排定或用户不存在时返回空的 null.Time。
func GetAccountDeletionScheduledAt(
	ctx context.Context,
	userID int64,
) (null.Time, *errs.Error) {
	var scheduledAt null.Time
	err := db.R.QueryRow(ctx, getAccountDeletionScheduledAtSQL, userID).Scan(&scheduledAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return null.Time{}, nil
		}
		return null.Time{}, errs.CreatePGError(err, "用户", "Failed to get account deletion schedule")
	}
	return scheduledAt, nil
}

// ---------------------------------------------------------------------------
// 取消注销
// ---------------------------------------------------------------------------

// cancelPendingAccountDeletionSQL 只清除「尚未到期」的注销排期，已到期的不再取消。
const cancelPendingAccountDeletionSQL = `
UPDATE users
SET deletion_scheduled_at = NULL
WHERE id = $1 AND deletion_scheduled_at > now() AND deleted_at IS NULL
`

// CancelPendingAccountDeletion 取消尚未到期的账号注销，返回是否确实取消了一条排期。
// 注意：到期或未排定的注销不会被本函数处理，调用方需自行判断返回值。
func CancelPendingAccountDeletion(ctx context.Context, userID int64) (bool, *errs.Error) {
	tag, err := db.R.Exec(ctx, cancelPendingAccountDeletionSQL, userID)
	if err != nil {
		return false, errs.CreatePGError(err, "用户", "Failed to cancel account deletion")
	}
	return tag.RowsAffected() > 0, nil
}

// ---------------------------------------------------------------------------
// 完成到期的注销（单用户）
// ---------------------------------------------------------------------------

// finalizeOverdueAccountDeletionSQL 在单条语句中原子完成到期注销：软删除用户、软删除邮箱/QQ、
// 删除密码/TOTP/用户组/授权、撤销会话、删除 OAuth 授权，并把其 OAuth 应用转归系统管理员。
const finalizeOverdueAccountDeletionSQL = `
WITH due AS (
    UPDATE users
    SET deleted_at = now(), deletion_scheduled_at = NULL
    WHERE id = $1 AND deletion_scheduled_at <= now() AND deleted_at IS NULL
    RETURNING id, username
),
emails AS (
    UPDATE user_emails
    SET deleted_at = now()
    WHERE user_id IN (SELECT id FROM due) AND deleted_at IS NULL
),
qqs AS (
    UPDATE user_qqs
    SET deleted_at = now()
    WHERE user_id IN (SELECT id FROM due) AND deleted_at IS NULL
),
passwords AS (
    DELETE FROM user_passwords WHERE user_id IN (SELECT id FROM due)
),
totps AS (
    DELETE FROM user_totp WHERE user_id IN (SELECT id FROM due)
),
roles AS (
    DELETE FROM user_roles WHERE user_id IN (SELECT id FROM due)
),
grants AS (
    DELETE FROM user_permission_grants WHERE user_id IN (SELECT id FROM due)
),
sessions AS (
    UPDATE user_sessions
    SET revoked_at = now()
    WHERE user_id IN (SELECT id FROM due) AND revoked_at IS NULL
),
auths AS (
    DELETE FROM oauth_authorizations WHERE user_id IN (SELECT id FROM due)
),
apps AS (
    UPDATE oauth_apps
    SET owner_user_id = $2
    WHERE owner_user_id IN (SELECT id FROM due) AND deleted_at IS NULL
)
SELECT id, username FROM due
`

// FinalizeOverdueAccountDeletion 完成指定用户已到期的注销（登录时调用），返回是否执行了清理。
// 注意：只有 deletion_scheduled_at <= now() 时才会生效；清理后用户资料仍保留但不可再登录。
func FinalizeOverdueAccountDeletion(ctx context.Context, userID int64) (bool, *errs.Error) {
	var id int64
	var username string
	err := db.R.QueryRow(
		ctx,
		finalizeOverdueAccountDeletionSQL,
		userID,
		systemAdminUserID,
	).Scan(&id, &username)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, errs.CreatePGError(err, "用户", "Failed to finalize account deletion")
	}
	db.R.Del(ctx, UserCacheKey(id))
	db.R.Del(ctx, UserIDCacheKey(username))
	return true, nil
}

// ---------------------------------------------------------------------------
// 完成到期的注销（批量）
// ---------------------------------------------------------------------------

// finalizeDueAccountDeletionsSQL 批量完成所有到期注销，逻辑与单用户版本相同，应用归属改为参数 $1。
const finalizeDueAccountDeletionsSQL = `
WITH due AS (
    UPDATE users
    SET deleted_at = now(), deletion_scheduled_at = NULL
    WHERE deletion_scheduled_at IS NOT NULL
      AND deletion_scheduled_at <= now()
      AND deleted_at IS NULL
    RETURNING id, username
),
emails AS (
    UPDATE user_emails
    SET deleted_at = now()
    WHERE user_id IN (SELECT id FROM due) AND deleted_at IS NULL
),
qqs AS (
    UPDATE user_qqs
    SET deleted_at = now()
    WHERE user_id IN (SELECT id FROM due) AND deleted_at IS NULL
),
passwords AS (
    DELETE FROM user_passwords WHERE user_id IN (SELECT id FROM due)
),
totps AS (
    DELETE FROM user_totp WHERE user_id IN (SELECT id FROM due)
),
roles AS (
    DELETE FROM user_roles WHERE user_id IN (SELECT id FROM due)
),
grants AS (
    DELETE FROM user_permission_grants WHERE user_id IN (SELECT id FROM due)
),
sessions AS (
    UPDATE user_sessions
    SET revoked_at = now()
    WHERE user_id IN (SELECT id FROM due) AND revoked_at IS NULL
),
auths AS (
    DELETE FROM oauth_authorizations WHERE user_id IN (SELECT id FROM due)
),
apps AS (
    UPDATE oauth_apps
    SET owner_user_id = $1
    WHERE owner_user_id IN (SELECT id FROM due) AND deleted_at IS NULL
)
SELECT id, username FROM due
`

// FinalizeDueAccountDeletions 批量完成所有到期注销，返回清理的用户数；由定时任务每 10 分钟调用。
// 注意：逐行清理对应用户的缓存再返回，失败时返回已清理的数量与错误。
func FinalizeDueAccountDeletions(ctx context.Context) (int64, *errs.Error) {
	rows, err := db.R.Query(ctx, finalizeDueAccountDeletionsSQL, systemAdminUserID)
	if err != nil {
		return 0, errs.CreatePGError(err, "用户", "Failed to finalize account deletions").AppendDetails("账号注销清理失败")
	}
	defer rows.Close()

	// 逐行扫描到期用户并清理其缓存

	var count int64
	for rows.Next() {
		var id int64
		var username string
		if err := rows.Scan(&id, &username); err != nil {
			return count, errs.CreatePGError(err, "用户", "Failed to scan finalized account").AppendDetails("账号注销清理失败")
		}
		count++
		db.R.Del(ctx, UserCacheKey(id))
		db.R.Del(ctx, UserIDCacheKey(username))
	}
	if err := rows.Err(); err != nil {
		return count, errs.CreatePGError(err, "用户", "Failed to finalize account deletions").AppendDetails("账号注销清理失败")
	}
	return count, nil
}

// ---------------------------------------------------------------------------
// 立即删除用户（管理员）
// ---------------------------------------------------------------------------

// adminDeleteUserSQL 管理员立即删除用户：逻辑与到期注销清理一致，但触发条件是用户 ID 而非注销排期。
const adminDeleteUserSQL = `
WITH deleted AS (
    UPDATE users
    SET deleted_at = now(), deletion_scheduled_at = NULL
    WHERE id = $1 AND deleted_at IS NULL
    RETURNING id, username
),
emails AS (
    UPDATE user_emails
    SET deleted_at = now()
    WHERE user_id IN (SELECT id FROM deleted) AND deleted_at IS NULL
),
qqs AS (
    UPDATE user_qqs
    SET deleted_at = now()
    WHERE user_id IN (SELECT id FROM deleted) AND deleted_at IS NULL
),
passwords AS (
    DELETE FROM user_passwords WHERE user_id IN (SELECT id FROM deleted)
),
totps AS (
    DELETE FROM user_totp WHERE user_id IN (SELECT id FROM deleted)
),
roles AS (
    DELETE FROM user_roles WHERE user_id IN (SELECT id FROM deleted)
),
grants AS (
    DELETE FROM user_permission_grants WHERE user_id IN (SELECT id FROM deleted)
),
sessions AS (
    UPDATE user_sessions
    SET revoked_at = now()
    WHERE user_id IN (SELECT id FROM deleted) AND revoked_at IS NULL
),
auths AS (
    DELETE FROM oauth_authorizations WHERE user_id IN (SELECT id FROM deleted)
),
apps AS (
    UPDATE oauth_apps
    SET owner_user_id = $2
    WHERE owner_user_id IN (SELECT id FROM deleted) AND deleted_at IS NULL
)
SELECT id, username FROM deleted
`

// DeleteUser 管理员立即删除用户：软删除用户并清理关联凭据/会话，其 OAuth 应用转归系统管理员。
// 用户不存在时返回 404；成功后清理用户信息、用户名映射与用户名占用缓存。
func DeleteUser(ctx context.Context, userID int64) *errs.Error {
	var id int64
	var username string
	err := db.R.QueryRow(ctx, adminDeleteUserSQL, userID, systemAdminUserID).Scan(&id, &username)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errs.NotFoundError().AppendDetails("用户不存在")
		}
		return errs.CreatePGError(err, "用户", "Failed to delete user")
	}

	db.R.Del(ctx, UserCacheKey(id))
	db.R.Del(ctx, UserIDCacheKey(username))
	db.R.Del(ctx, UsernameExistsCacheKey(username))

	return nil
}
