package user

import (
	"context"
	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// UserBanCacheDuration 是封禁信息缓存时长；较短以保证封禁/解封后尽快生效。
const UserBanCacheDuration = 1 * time.Minute

// UserBanCacheKey 返回封禁信息缓存的 Redis key（按用户 ID）。
func UserBanCacheKey(userID int64) string {
	return fmt.Sprintf("student_id:user:ban:%d", userID)
}

// banUserSQL 在单条语句中先禁用该用户已有的启用中封禁，再插入新封禁，保证同一用户最多一条启用记录。
const banUserSQL = `
WITH disabled AS (
    UPDATE user_bans
    SET enabled = false
    WHERE user_id = $1 AND enabled = true
)
INSERT INTO user_bans (user_id, reason, end_time, enabled)
VALUES ($1, $2, $3, true)
RETURNING id, created_at
`

// BanUser 封禁用户：禁用其旧封禁、写入新封禁记录并失效封禁缓存；end_time 为空表示永久封禁。
// 注意：不校验用户是否存在与是否重复封禁，调用方需先确认目标用户存在。
func BanUser(ctx context.Context, b *model.UserBan) *errs.Error {
	err := db.R.Pool.QueryRow(ctx, banUserSQL,
		b.UserID, b.Reason, b.EndTime,
	).Scan(&b.ID, &b.CreatedAt)
	if err != nil {
		return errs.CreatePGError(err, "封禁信息", "Failed to ban user")
	}

	db.R.Del(ctx, UserBanCacheKey(b.UserID))
	return nil
}

// unbanUserSQL 禁用该用户所有启用中的封禁记录。
const unbanUserSQL = `
UPDATE user_bans
SET enabled = false
WHERE user_id = $1 AND enabled = true
`

// UnbanUser 解除用户封禁并失效封禁缓存；用户未被封禁时更新 0 行也视为成功（幂等）。
func UnbanUser(ctx context.Context, userID int64) *errs.Error {
	if _, err := db.R.Pool.Exec(ctx, unbanUserSQL, userID); err != nil {
		return errs.CreatePGError(err, "封禁信息", "Failed to unban user")
	}
	db.R.Del(ctx, UserBanCacheKey(userID))
	return nil
}

// getUserBanSQL 查询用户当前有效的封禁记录，并顺手把已过期的启用中封禁置为失效。
const getUserBanSQL = `
WITH expire AS (
    UPDATE user_bans
    SET enabled = false
    WHERE user_id = $1 AND enabled = true AND end_time IS NOT NULL AND end_time <= now()
)
SELECT id, user_id, reason, end_time, created_at, enabled
FROM user_bans
WHERE user_id = $1 AND enabled = true AND (end_time IS NULL OR end_time > now())
`

// GetUserBan 查询用户当前生效的封禁记录，结果缓存 1 分钟；未封禁时返回 nil，不返回错误。
// 注意：查询会顺带禁用已过期封禁；缓存命中后仍会再判断一次 end_time，过期则删缓存并返回 nil。
func GetUserBan(ctx context.Context, userID int64) (*model.UserBan, *errs.Error) {
	ban, err := db.GetCached(
		ctx,
		"封禁信息",
		UserBanCacheKey(userID),
		UserBanCacheDuration,
		func() (*model.UserBan, error) {
			var b model.UserBan
			err := db.R.QueryRow(ctx, getUserBanSQL, userID).Scan(
				&b.ID, &b.UserID, &b.Reason, &b.EndTime, &b.CreatedAt, &b.Enabled,
			)
			return &b, err
		},
	)
	if err != nil {
		return nil, err
	}
	if ban != nil && ban.EndTime.Valid && !ban.EndTime.Time.After(time.Now()) {
		db.R.Del(ctx, UserBanCacheKey(userID))
		return nil, nil
	}
	return ban, nil
}

// cleanupExpiredBansSQL 批量禁用所有已到期的封禁记录，返回受影响的用户 ID 用于清理缓存。
const cleanupExpiredBansSQL = `
UPDATE user_bans
SET enabled = false
WHERE enabled = true AND end_time IS NOT NULL AND end_time <= now()
RETURNING user_id
`

// CleanupExpiredBans 批量禁用已过期的封禁并清理对应缓存，返回清理条数；由定时任务每 10 分钟调用。
func CleanupExpiredBans(ctx context.Context) (int64, *errs.Error) {
	rows, err := db.R.Pool.Query(ctx, cleanupExpiredBansSQL)
	if err != nil {
		return 0, errs.CreatePGError(err, "封禁信息", "Failed to cleanup expired bans").
			AppendDetails("过期封禁清理失败")
	}

	userIDs, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (int64, error) {
		var userID int64
		err := row.Scan(&userID)
		return userID, err
	})
	if err != nil {
		return 0, errs.CreatePGError(err, "封禁信息", "Failed to collect expired bans").
			AppendDetails("过期封禁清理失败")
	}

	for _, userID := range userIDs {
		db.R.Del(ctx, UserBanCacheKey(userID))
	}

	return int64(len(userIDs)), nil
}
