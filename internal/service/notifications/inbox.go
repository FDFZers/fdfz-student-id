package notifications

import (
	"context"
	"errors"

	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"

	"github.com/jackc/pgx/v5"
)

// Source 是站内通知来源：App 与 UserID 二者有且仅有一个有效；管理员来源对用户只展示「管理员」。
type Source struct {
	App    *model.OAuthApp
	UserID int64
}

const notificationSelectSQL = `
SELECT n.id, n.user_id, u.username, u.nickname,
    n.app_id, COALESCE(a.name, ''), COALESCE(a.namespace, ''),
    n.sender_user_id, COALESCE(su.username, ''), su.nickname,
    n.icon, n.title, n.content, n.ext, n.read_at, n.created_at
FROM notifications n
JOIN users u ON u.id = n.user_id
LEFT JOIN apps a ON a.id = n.app_id
LEFT JOIN users su ON su.id = n.sender_user_id`

const insertInAppSQL = `
INSERT INTO notifications (user_id, app_id, sender_user_id, icon, title, content, ext)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING id, user_id, app_id, sender_user_id, icon, title, content, ext, read_at, created_at`

const selectInAppSQL = notificationSelectSQL + `
WHERE n.user_id = $1
  AND (NOT $2 OR n.read_at IS NULL)
ORDER BY n.created_at DESC, n.id DESC
LIMIT $3 OFFSET $4`

const countInAppSQL = `
SELECT count(*)
FROM notifications
WHERE user_id = $1
  AND (NOT $2 OR read_at IS NULL)`

const countInAppUnreadSQL = `
SELECT count(*)
FROM notifications
WHERE user_id = $1 AND read_at IS NULL`

const selectInAppByIDSQL = notificationSelectSQL + `
WHERE n.id = $1 AND n.user_id = $2`

const markInAppReadSQL = `
UPDATE notifications
SET read_at = now()
WHERE id = $1 AND user_id = $2 AND read_at IS NULL`

const markAllInAppReadSQL = `
UPDATE notifications
SET read_at = now()
WHERE user_id = $1 AND read_at IS NULL`

const deleteInAppSQL = `
DELETE FROM notifications
WHERE id = $1 AND user_id = $2`

func scanNotification(row pgx.Row) (*model.Notification, error) {
	notification := &model.Notification{}
	err := row.Scan(
		&notification.ID,
		&notification.UserID,
		&notification.RecipientUsername,
		&notification.RecipientNickname,
		&notification.AppID,
		&notification.AppName,
		&notification.AppNamespace,
		&notification.SenderUserID,
		&notification.SenderUsername,
		&notification.SenderNickname,
		&notification.Icon,
		&notification.Title,
		&notification.Content,
		&notification.Ext,
		&notification.ReadAt,
		&notification.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	if notification.Ext == nil {
		notification.Ext = map[string]any{}
	}
	return notification, nil
}

// CreateInApp 写入一条站内通知；source 必须且只能指定应用或管理员之一，调用方应先用 ValidateMessage 校验内容。
func CreateInApp(
	ctx context.Context,
	userID int64,
	source Source,
	msg Message,
) (*model.Notification, *errs.Error) {
	if (source.App == nil) == (source.UserID == 0) {
		return nil, errs.BadRequestError().AppendDetails("站内通知来源必须且只能有一个")
	}

	ext := msg.Ext
	if ext == nil {
		ext = map[string]any{}
	}

	var appID any
	if source.App != nil {
		appID = source.App.ID
	}
	var senderUserID any
	if source.UserID > 0 {
		senderUserID = source.UserID
	}

	notification := &model.Notification{}
	if source.App != nil {
		notification.AppName = source.App.Name
		notification.AppNamespace = source.App.Namespace
	}
	err := db.R.QueryRow(
		ctx, insertInAppSQL,
		userID, appID, senderUserID, msg.Icon, msg.Title, msg.Markdown, ext,
	).Scan(
		&notification.ID,
		&notification.UserID,
		&notification.AppID,
		&notification.SenderUserID,
		&notification.Icon,
		&notification.Title,
		&notification.Content,
		&notification.Ext,
		&notification.ReadAt,
		&notification.CreatedAt,
	)
	if err != nil {
		return nil, errs.CreatePGError(err, "站内通知", "Failed to create in-app notification").
			AppendDetails("站内通知写入失败")
	}
	if notification.Ext == nil {
		notification.Ext = map[string]any{}
	}
	return notification, nil
}

// ListInApp 分页查询用户的站内通知，同时返回符合过滤条件的总数与用户全部未读数。
func ListInApp(
	ctx context.Context,
	userID int64,
	unreadOnly bool,
	limit, offset int32,
) ([]*model.Notification, int64, int64, *errs.Error) {
	var count int64
	if err := db.R.QueryRow(ctx, countInAppSQL, userID, unreadOnly).Scan(&count); err != nil {
		return nil, 0, 0, errs.CreatePGError(err, "站内通知", "Failed to count in-app notifications").
			AppendDetails("站内通知总数获取失败")
	}

	var unread int64
	if err := db.R.QueryRow(ctx, countInAppUnreadSQL, userID).Scan(&unread); err != nil {
		return nil, 0, 0, errs.CreatePGError(err, "站内通知", "Failed to count unread in-app notifications").
			AppendDetails("站内通知未读数获取失败")
	}

	rows, err := db.R.Query(ctx, selectInAppSQL, userID, unreadOnly, limit, offset)
	if err != nil {
		return nil, 0, 0, errs.CreatePGError(err, "站内通知", "Failed to list in-app notifications").
			AppendDetails("站内通知列表获取失败")
	}
	defer rows.Close()

	notifications := make([]*model.Notification, 0, limit)
	for rows.Next() {
		notification, scanErr := scanNotification(rows)
		if scanErr != nil {
			return nil, 0, 0, errs.CreatePGError(scanErr, "站内通知", "Failed to scan in-app notification").
				AppendDetails("站内通知解析失败")
		}
		notifications = append(notifications, notification)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, 0, errs.CreatePGError(err, "站内通知", "Failed to iterate in-app notifications").
			AppendDetails("站内通知列表读取失败")
	}

	return notifications, count, unread, nil
}

func GetInApp(ctx context.Context, userID, id int64) (*model.Notification, *errs.Error) {
	notification, err := scanNotification(db.R.QueryRow(ctx, selectInAppByIDSQL, id, userID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, errs.CreatePGError(err, "站内通知", "Failed to get in-app notification").
			AppendDetails("站内通知获取失败")
	}
	return notification, nil
}

// MarkInAppRead 返回 false 表示通知不存在或不属于该用户。
func MarkInAppRead(ctx context.Context, userID, id int64) (bool, *errs.Error) {
	notification, err := GetInApp(ctx, userID, id)
	if err != nil {
		return false, err
	}
	if notification == nil {
		return false, nil
	}
	if notification.ReadAt.Valid {
		return true, nil
	}

	if _, execErr := db.R.Exec(ctx, markInAppReadSQL, id, userID); execErr != nil {
		return false, errs.CreatePGError(execErr, "站内通知", "Failed to mark in-app notification as read").
			AppendDetails("站内通知标记已读失败")
	}
	return true, nil
}

func MarkAllInAppRead(ctx context.Context, userID int64) (int64, *errs.Error) {
	tag, err := db.R.Exec(ctx, markAllInAppReadSQL, userID)
	if err != nil {
		return 0, errs.CreatePGError(err, "站内通知", "Failed to mark all in-app notifications as read").
			AppendDetails("站内通知标记已读失败")
	}
	return tag.RowsAffected(), nil
}

func DeleteInApp(ctx context.Context, userID, id int64) (bool, *errs.Error) {
	tag, err := db.R.Exec(ctx, deleteInAppSQL, id, userID)
	if err != nil {
		return false, errs.CreatePGError(err, "站内通知", "Failed to delete in-app notification").
			AppendDetails("站内通知删除失败")
	}
	return tag.RowsAffected() > 0, nil
}
