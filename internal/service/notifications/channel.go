package notifications

import (
	"fmt"
	"slices"
	"strings"

	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
)

// DefaultChannels 返回默认投递渠道：站内、邮件、QQ。
func DefaultChannels() []model.NotificationChannel {
	return model.NotificationChannelValues()
}

// ParseChannels 把渠道名解析为去重列表；空列表按未提供处理，返回默认渠道。
func ParseChannels(raw []string) ([]model.NotificationChannel, *errs.Error) {
	if len(raw) == 0 {
		return DefaultChannels(), nil
	}

	channels := make([]model.NotificationChannel, 0, len(raw))
	for _, item := range raw {
		value := strings.ToLower(strings.TrimSpace(item))
		if value == "" {
			continue
		}
		channel, parseErr := model.ParseNotificationChannel(value)
		if parseErr != nil {
			return nil, errs.BadRequestError().AppendDetails(
				fmt.Sprintf("未知的通知渠道：%s", item),
				"可用渠道："+strings.Join(model.NotificationChannelNames(), "、"),
			)
		}
		if !slices.Contains(channels, channel) {
			channels = append(channels, channel)
		}
	}

	if len(channels) == 0 {
		return DefaultChannels(), nil
	}
	return channels, nil
}

func ChannelStrings(channels []model.NotificationChannel) []string {
	result := make([]string, 0, len(channels))
	for _, channel := range channels {
		result = append(result, channel.String())
	}
	return result
}

// Target 通知接收目标：UserID 用于站内通知，Email 与 QQ 用于外部渠道。
type Target struct {
	UserID int64
	Email  string
	QQ     string
}

type Result struct {
	Notification *model.Notification         // 站内通知记录；未投递站内渠道时为 nil
	Channels     []model.NotificationChannel // 实际投递（邮件、QQ 为已排队）的渠道
}
