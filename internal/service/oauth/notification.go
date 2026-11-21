package oauth

import (
	"context"
	"errors"

	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"

	"github.com/jackc/pgx/v5"
)

const userAllowsAppNotificationsSQL = `
SELECT a.allow_notifications, u.app_notifications_enabled
FROM oauth_authorizations a
JOIN users u ON u.id = a.user_id
WHERE a.user_id = $1 AND a.app_id = $2 AND a.status = 'active' AND u.deleted_at IS NULL`

// UserAllowsAppNotifications 判断应用能否向指定用户发送通知：授权有效、授权时用户允许且未关闭应用通知总开关。
func UserAllowsAppNotifications(ctx context.Context, userID, appID int64) (bool, *errs.Error) {
	var allow, enabled bool
	err := db.R.QueryRow(ctx, userAllowsAppNotificationsSQL, userID, appID).Scan(&allow, &enabled)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, errs.CreatePGError(err, "应用通知", "Failed to check app notification permission").
			AppendDetails("应用通知权限查询失败")
	}
	return allow && enabled, nil
}
