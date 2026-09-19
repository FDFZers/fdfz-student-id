package user

import (
	"context"
	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fmt"
	"time"
)

const UserBanCacheDuration = 1 * time.Minute

func UserBanCacheKey(userID int64) string {
	return fmt.Sprintf("user:ban:%d", userID)
}

const banUserSQL = `
WITH disabled AS (
    UPDATE user_bans
    SET enabled = false
    WHERE user_id = $1 AND enabled = true
    RETURNING id
)
INSERT INTO user_bans (user_id, reason, end_time, enabled)
VALUES ($1, $2, $3, true)
RETURNING id, created_at
`

func BanUser(ctx context.Context, b *model.UserBan) *errs.Error {
	err := db.R.Pool.QueryRow(ctx, banUserSQL,
		b.UserID, b.Reason, b.EndTime,
	).Scan(&b.ID, &b.CreatedAt)
	if err != nil {
		return errs.CreatePGError(err, "封禁信息", "Failed to ban user").AppendDetails("用户封禁失败")
	}

	db.R.Del(ctx, UserBanCacheKey(b.UserID))
	return nil
}

const unbanUserSQL = `
UPDATE user_bans
SET enabled = false
WHERE user_id = $1 AND enabled = true
`

func UnbanUser(ctx context.Context, userID int64) *errs.Error {
	if _, err := db.R.Pool.Exec(ctx, unbanUserSQL, userID); err != nil {
		return errs.CreatePGError(err, "封禁信息", "Failed to unban user").AppendDetails("用户解封失败")
	}
	db.R.Del(ctx, UserBanCacheKey(userID))
	return nil
}

const getUserBanSQL = `
WITH expire AS (
    UPDATE user_bans
    SET enabled = false
    WHERE user_id = $1 AND enabled = true AND end_time IS NOT NULL AND end_time <= now()
)
SELECT id, user_id, reason, end_time, created_at
FROM user_bans
WHERE user_id = $1  AND enabled = true AND (end_time IS NULL OR end_time > now())
`

func GetUserBan(ctx context.Context, userID int64) (*model.UserBan, *errs.Error) {
	ban, err := db.GetCached(
		ctx,
		"封禁信息",
		UserBanCacheKey(userID),
		UserBanCacheDuration,
		func() (*model.UserBan, error) {
			var b model.UserBan
			err := db.R.QueryRow(ctx, getUserBanSQL, userID).Scan(
				&b.ID, &b.UserID, &b.Reason, &b.EndTime, &b.CreatedAt,
			)
			return &b, err
		},
	)
	if err != nil {
		return nil, err.AppendDetails("封禁信息获取失败")
	}
	return ban, nil
}
