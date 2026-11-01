package user

import (
	"context"
	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
	"time"

	"github.com/guregu/null/v6"
)

const AccountDeletionDelay = 7 * 24 * time.Hour

// ---------------------------------------------------------------------------
// 申请注销
// ---------------------------------------------------------------------------

const scheduleAccountDeletionSQL = `
UPDATE users
SET deletion_scheduled_at = COALESCE(deletion_scheduled_at, now() + make_interval(secs => $2))
WHERE id = $1 AND deleted_at IS NULL
RETURNING deletion_scheduled_at
`

func ScheduleAccountDeletion(
	ctx context.Context,
	userID int64,
	delay time.Duration,
) (time.Time, *errs.Error) {
	var scheduledAt time.Time
	err := db.R.QueryRow(ctx, scheduleAccountDeletionSQL, userID, delay.Seconds()).Scan(&scheduledAt)
	if err != nil {
		return time.Time{}, errs.CreatePGError(err, "用户", "Failed to schedule account deletion").AppendDetails("账号注销申请失败")
	}
	return scheduledAt, nil
}

// ---------------------------------------------------------------------------
// 获取注销时间
// ---------------------------------------------------------------------------

const getAccountDeletionScheduledAtSQL = `
SELECT deletion_scheduled_at FROM users WHERE id = $1 AND deleted_at IS NULL
`

func GetAccountDeletionScheduledAt(
	ctx context.Context,
	userID int64,
) (null.Time, *errs.Error) {
	var scheduledAt null.Time
	err := db.R.QueryRow(ctx, getAccountDeletionScheduledAtSQL, userID).Scan(&scheduledAt)
	if err != nil {
		return null.Time{}, errs.CreatePGError(err, "用户", "Failed to get account deletion schedule").AppendDetails("账号注销信息获取失败")
	}
	return scheduledAt, nil
}

// ---------------------------------------------------------------------------
// 取消注销
// ---------------------------------------------------------------------------

const cancelPendingAccountDeletionSQL = `
UPDATE users
SET deletion_scheduled_at = NULL
WHERE id = $1 AND deletion_scheduled_at > now() AND deleted_at IS NULL
`

func CancelPendingAccountDeletion(ctx context.Context, userID int64) (bool, *errs.Error) {
	tag, err := db.R.Exec(ctx, cancelPendingAccountDeletionSQL, userID)
	if err != nil {
		return false, errs.CreatePGError(err, "用户", "Failed to cancel account deletion").AppendDetails("账号注销取消失败")
	}
	return tag.RowsAffected() > 0, nil
}

// ---------------------------------------------------------------------------
// 完成到期的注销
// ---------------------------------------------------------------------------

const finalizeOverdueAccountDeletionSQL = `
WITH due AS (
    UPDATE users
    SET deleted_at = now()
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
)
SELECT id, username FROM due
`

func FinalizeOverdueAccountDeletion(ctx context.Context, userID int64) (bool, *errs.Error) {
	var id int64
	var username string
	err := db.R.QueryRow(ctx, finalizeOverdueAccountDeletionSQL, userID).Scan(&id, &username)
	if err != nil {
		e := errs.CreatePGError(err, "用户", "Failed to finalize account deletion")
		if e.Info.Error == "not_found" {
			return false, nil
		}
		return false, e.AppendDetails("账号注销失败")
	}
	db.R.Del(ctx, UserCacheKey(id))
	db.R.Del(ctx, UserIDCacheKey(username))
	return true, nil
}

const finalizeDueAccountDeletionsSQL = `
WITH due AS (
    UPDATE users
    SET deleted_at = now()
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
)
SELECT id, username FROM due
`

func FinalizeDueAccountDeletions(ctx context.Context) (int64, *errs.Error) {
	rows, err := db.R.Query(ctx, finalizeDueAccountDeletionsSQL)
	if err != nil {
		return 0, errs.CreatePGError(err, "用户", "Failed to finalize account deletions").AppendDetails("账号注销清理失败")
	}
	defer rows.Close()

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
