package notification

import (
	"net/http"
	"net/mail"
	"slices"
	"strings"

	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	notificationsvc "fdfz-student-id/internal/service/notifications"
	"fdfz-student-id/internal/util/handling"

	"github.com/gin-gonic/gin"
)

// sendRequest 是统一通知发送接口的请求体；email/qq 为空时使用用户当前绑定，app_id 为 0 时来源为当前管理员。
type sendRequest struct {
	UserID   int64          `json:"user_id"` // 接收用户
	Email    string         `json:"email"`
	QQ       string         `json:"qq"`
	Channels []string       `json:"channels"`
	AppID    int64          `json:"app_id"` // 来源应用 ID；为 0 时来源为当前管理员
	Icon     string         `json:"icon"`   // Lucide 图标名，仅站内通知使用
	Title    string         `json:"title"`
	Desc     string         `json:"desc"`
	Content  string         `json:"content"` // Markdown 正文
	Ext      map[string]any `json:"ext"`
}

// sendHandler 向指定用户或地址发送通知，支持按渠道选择；站内通知同步写库，邮件与 QQ 异步发送。
func sendHandler(c *gin.Context) *errs.Error {
	var req sendRequest
	if err := handling.BindJSON(c, &req); err != nil {
		return err
	}

	claims := handling.MustGetClaims(c)

	channels, err := notificationsvc.ParseChannels(req.Channels)
	if err != nil {
		return err
	}

	msg := notificationsvc.NewMarkdownMessage(req.Title, req.Desc, req.Content, req.Ext)
	msg.AppID = req.AppID
	if req.AppID == 0 {
		msg.SenderUserID = claims.UserID
	}
	msg.Icon = req.Icon
	if err := notificationsvc.ValidateMessage(&msg); err != nil {
		return err
	}

	target := notificationsvc.Target{
		UserID: req.UserID,
		Email:  strings.TrimSpace(req.Email),
		QQ:     strings.TrimSpace(req.QQ),
	}
	if target.UserID < 0 {
		return errs.BadRequestError().AppendDetails("用户 ID 格式错误")
	}
	if slices.Contains(channels, model.NotificationChannelInapp) && target.UserID <= 0 {
		return errs.BadRequestError().AppendDetails("发送站内通知必须指定用户 ID")
	}
	if target.UserID > 0 {
		if e := handling.EnsureUserExists(c, target.UserID); e != nil {
			return e
		}
	}
	if target.Email != "" {
		address, parseErr := mail.ParseAddress(target.Email)
		if parseErr != nil || address.Address != target.Email || len(target.Email) > 254 {
			return errs.BadRequestError().AppendDetails("邮箱格式错误")
		}
	}
	if target.QQ != "" {
		if e := handling.ValidateQQ(target.QQ); e != nil {
			return e
		}
	}

	target, err = notificationsvc.ResolveTarget(c.Request.Context(), target, channels)
	if err != nil {
		return err
	}

	result, err := notificationsvc.Send(c.Request.Context(), target, msg, channels)
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

// skippedChannels 返回请求了但未实际投递的渠道。
func skippedChannels(requested, delivered []model.NotificationChannel) []string {
	skipped := make([]string, 0, len(requested))
	for _, channel := range requested {
		if !slices.Contains(delivered, channel) {
			skipped = append(skipped, string(channel))
		}
	}
	return skipped
}
