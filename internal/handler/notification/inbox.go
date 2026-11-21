package notification

import (
	"net/http"
	"strconv"
	"time"

	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	notificationsvc "fdfz-student-id/internal/service/notifications"
	searchsvc "fdfz-student-id/internal/service/search"
	"fdfz-student-id/internal/util/handling"

	"github.com/gin-gonic/gin"
	"github.com/guregu/null/v6"
)

// ---------------------------------------------------------------------------
// 用户自己的通知响应：接收方只能看到来源类型与展示名，不能看到管理员发送者 ID。
// ---------------------------------------------------------------------------

type selfNotification struct {
	ID           int64          `json:"id"`
	UserID       int64          `json:"user_id"`
	Source       string         `json:"source"`
	SourceName   string         `json:"source_name"`
	AppID        *int64         `json:"app_id"`
	AppName      string         `json:"app_name,omitempty"`
	AppNamespace string         `json:"app_namespace,omitempty"`
	Icon         string         `json:"icon"`
	Title        string         `json:"title"`
	Content      string         `json:"content"`
	Ext          map[string]any `json:"ext"`
	ReadAt       null.Time      `json:"read_at"`
	CreatedAt    time.Time      `json:"created_at"`
}

func selfNotificationJSON(notification *model.Notification) *selfNotification {
	view := &selfNotification{
		ID:         notification.ID,
		UserID:     notification.UserID,
		Source:     "admin",
		SourceName: "管理员",
		Icon:       notification.Icon,
		Title:      notification.Title,
		Content:    notification.Content,
		Ext:        notification.Ext,
		ReadAt:     notification.ReadAt,
		CreatedAt:  notification.CreatedAt,
	}
	if notification.AppID.Valid {
		appID := notification.AppID.Int64
		view.Source = "app"
		view.SourceName = notification.AppName
		if view.SourceName == "" {
			view.SourceName = notification.AppNamespace
		}
		if view.SourceName == "" {
			view.SourceName = "应用"
		}
		view.AppID = &appID
		view.AppName = notification.AppName
		view.AppNamespace = notification.AppNamespace
	}
	return view
}

func selfNotificationsJSON(notifications []*model.Notification) []*selfNotification {
	result := make([]*selfNotification, 0, len(notifications))
	for _, notification := range notifications {
		result = append(result, selfNotificationJSON(notification))
	}
	return result
}

// listHandler 分页查询当前用户的站内通知，响应附带该用户全部未读数。
func listHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)

	limit, offset := searchsvc.ParseQueryPagination(c)
	unreadOnly, err := parseUnreadQuery(c)
	if err != nil {
		return err
	}

	notifications, count, unread, err := notificationsvc.ListInApp(
		c.Request.Context(), claims.UserID, unreadOnly, limit, offset,
	)
	if err != nil {
		return err
	}

	c.JSON(http.StatusOK, gin.H{
		"count":  count,
		"unread": unread,
		"data":   selfNotificationsJSON(notifications),
	})
	return nil
}

// getHandler 查询当前用户的一条站内通知；他人的通知一律按不存在处理。
func getHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)

	id, err := handling.ParseID(c, "id", "通知")
	if err != nil {
		return err
	}

	notification, err := notificationsvc.GetInApp(c.Request.Context(), claims.UserID, id)
	if err != nil {
		return err
	}
	if notification == nil {
		return errs.NotFoundError().AppendDetails("通知不存在")
	}

	c.JSON(http.StatusOK, selfNotificationJSON(notification))
	return nil
}

// markReadHandler 把当前用户的一条站内通知标记为已读（幂等）。
func markReadHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)

	id, err := handling.ParseID(c, "id", "通知")
	if err != nil {
		return err
	}

	found, err := notificationsvc.MarkInAppRead(c.Request.Context(), claims.UserID, id)
	if err != nil {
		return err
	}
	if !found {
		return errs.NotFoundError().AppendDetails("通知不存在")
	}

	handling.RespondOK(c)
	return nil
}

func markAllReadHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)

	count, err := notificationsvc.MarkAllInAppRead(c.Request.Context(), claims.UserID)
	if err != nil {
		return err
	}

	c.JSON(http.StatusOK, gin.H{"count": count})
	return nil
}

func deleteHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)

	id, err := handling.ParseID(c, "id", "通知")
	if err != nil {
		return err
	}

	found, err := notificationsvc.DeleteInApp(c.Request.Context(), claims.UserID, id)
	if err != nil {
		return err
	}
	if !found {
		return errs.NotFoundError().AppendDetails("通知不存在")
	}

	handling.RespondOK(c)
	return nil
}

func parseUnreadQuery(c *gin.Context) (bool, *errs.Error) {
	raw := c.Query("unread")
	if raw == "" {
		return false, nil
	}

	unread, err := strconv.ParseBool(raw)
	if err != nil {
		return false, errs.BadRequestError().AppendDetails("unread 参数格式错误")
	}
	return unread, nil
}
