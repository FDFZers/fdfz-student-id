package auth

import (
	"context"
	"fdfz-student-id/internal/cfg"
	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
	"fmt"
	"time"
)

func StepupRevokedCacheKey(userID int64) string {
	return fmt.Sprintf("student_id:auth:stepup_revoked:%d", userID)
}

func RevokeUserStepups(ctx context.Context, userID int64) *errs.Error {
	if err := db.SetRedis(ctx, StepupRevokedCacheKey(userID), time.Now().Unix(), cfg.C.StepupTokenTTL); err != nil {
		return err.AppendDetails("提权令牌失效失败")
	}
	return nil
}

func GetStepupRevokedAt(ctx context.Context, userID int64) (time.Time, *errs.Error) {
	revokedAt, err := db.GetRedis[int64](ctx, StepupRevokedCacheKey(userID))
	if err != nil {
		return time.Time{}, err.AppendDetails("提权令牌状态获取失败")
	}
	if revokedAt == nil {
		return time.Time{}, nil
	}
	return time.Unix(*revokedAt, 0), nil
}
