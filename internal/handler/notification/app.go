package notification

import (
	"net/http"

	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	notificationsvc "fdfz-student-id/internal/service/notifications"
	oauthsvc "fdfz-student-id/internal/service/oauth"
	"fdfz-student-id/internal/util/handling"

	"github.com/gin-gonic/gin"
)

// appSendRequest 是第三方应用发送通知的请求体；来源应用固定为客户端密钥认证通过的应用。
type appSendRequest struct {
	ClientID     string         `json:"client_id"`
	ClientSecret string         `json:"client_secret"`
	UserID       int64          `json:"user_id"`
	Channels     []string       `json:"channels"` // 可选，缺省只发站内通知
	Icon         string         `json:"icon"`
	Title        string         `json:"title"`
	Desc         string         `json:"desc"`
	Content      string         `json:"content"` // Markdown 正文
	Ext          map[string]any `json:"ext"`
}

// appSendHandler 校验应用客户端密钥与用户授权后发送通知。
func appSendHandler(c *gin.Context) *errs.Error {
	var req appSendRequest
	if err := handling.BindJSON(c, &req); err != nil {
		return err
	}
	if req.UserID <= 0 {
		return errs.BadRequestError().AppendDetails("用户 ID 格式错误")
	}

	app, err := oauthsvc.AuthenticateClientWithSecret(c.Request.Context(), req.ClientID, req.ClientSecret)
	if err != nil {
		return err
	}

	// 应用通知默认只发站内，显式指定时才允许其它渠道
	channels := []model.NotificationChannel{model.NotificationChannelInapp}
	if len(req.Channels) > 0 {
		channels, err = notificationsvc.ParseChannels(req.Channels)
		if err != nil {
			return err
		}
	}

	msg := notificationsvc.NewMarkdownMessage(req.Title, req.Desc, req.Content, req.Ext)
	msg.Icon = req.Icon

	result, err := notificationsvc.SendFromApp(c.Request.Context(), app, req.UserID, msg, channels)
	if err != nil {
		return err
	}

	var notificationID *int64
	if result.Notification != nil {
		notificationID = &result.Notification.ID
	}

	c.JSON(http.StatusOK, gin.H{
		"notification_id": notificationID,
		"channels":        notificationsvc.ChannelStrings(result.Channels),
		"skipped":         skippedChannels(channels, result.Channels),
	})
	return nil
}
