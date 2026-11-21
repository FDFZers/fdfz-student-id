//go:generate go tool go-enum --names --values --marshal --sql
package model

import (
	"time"

	"github.com/guregu/null/v6"
)

// NotificationChannel 是通知投递渠道：inapp 站内通知、email 邮件、qq QQ 私聊。
// ENUM(inapp, email, QQ = qq)
type NotificationChannel string

// Notification 站内通知：来源为 AppID 或 SenderUserID 二选一，
// 名称字段均由查询时关联的 apps、users 表得到，不单独存储。
type Notification struct {
	ID                int64       `json:"id" db:"id"`
	UserID            int64       `json:"user_id" db:"user_id"`
	RecipientUsername string      `json:"recipient_username" db:"recipient_username"`
	RecipientNickname null.String `json:"recipient_nickname" db:"recipient_nickname"`

	AppID        null.Int `json:"app_id" db:"app_id"` // 来源应用；管理员发送时为 NULL
	AppName      string   `json:"app_name" db:"app_name"`
	AppNamespace string   `json:"app_namespace" db:"app_namespace"`

	SenderUserID   null.Int    `json:"sender_user_id" db:"sender_user_id"` // 来源管理员；应用发送时为 NULL
	SenderUsername string      `json:"sender_username" db:"sender_username"`
	SenderNickname null.String `json:"sender_nickname" db:"sender_nickname"`

	Icon      string         `json:"icon" db:"icon"` // Lucide 图标名，未指定时写入默认图标
	Title     string         `json:"title" db:"title"`
	Content   string         `json:"content" db:"content"` // Markdown 正文
	Ext       map[string]any `json:"ext" db:"ext"`         // 结构化附加信息，恒为 JSON 对象
	ReadAt    null.Time      `json:"read_at" db:"read_at"`
	CreatedAt time.Time      `json:"created_at" db:"created_at"`
}
