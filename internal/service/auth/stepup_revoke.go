package auth

import (
	"context"
	"fdfz-student-id/internal/cfg"
	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
	"fmt"
	"time"
)

// StepupRevokedCacheKey 返回记录用户提权令牌统一失效时间的 Redis 键。
func StepupRevokedCacheKey(userID int64) string {
	return fmt.Sprintf("student_id:auth:stepup_revoked:%d", userID)
}

// RevokeUserStepups 记录当前时间作为失效时间点，使该用户此前签发的提权令牌全部失效。
// 注意：记录只保留 StepupTokenTTL，超过该时长后旧提权令牌本身也已过期，无需继续保留。
func RevokeUserStepups(ctx context.Context, userID int64) *errs.Error {
	if err := db.SetRedis(ctx, StepupRevokedCacheKey(userID), time.Now().Unix(), cfg.C.StepupTokenTTL); err != nil {
		return err
	}
	return nil
}

// GetStepupRevokedAt 读取用户提权令牌的失效时间点，未记录时返回零值时间。
func GetStepupRevokedAt(ctx context.Context, userID int64) (time.Time, *errs.Error) {
	revokedAt, err := db.GetRedis[int64](ctx, StepupRevokedCacheKey(userID))
	if err != nil {
		return time.Time{}, err
	}
	if revokedAt == nil {
		return time.Time{}, nil
	}
	return time.Unix(*revokedAt, 0), nil
}
