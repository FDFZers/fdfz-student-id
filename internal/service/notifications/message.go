package notifications

import (
	"encoding/json/v2"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"fdfz-student-id/internal/errs"
)

const (
	// 与 notifications.title 列宽对齐（PostgreSQL 按字符计数）。
	maxTitleRunes = 256
	// 邮件预header 长度上限。
	maxDescRunes = 256
	// Markdown 正文长度上限。
	maxContentBytes = 64 << 10
	// ext 序列化后长度上限。
	maxExtBytes = 16 << 10
	// 与 notifications.icon 列宽对齐。
	maxIconLen = 64
	// 未指定图标时使用的 Lucide 图标名。
	DefaultIcon = "bell"
)

// iconPattern 匹配 Lucide 图标名：小写字母/数字分段，连字符连接。
var iconPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

var chinaTimeZone = time.FixedZone("CST", 8*60*60)

// BeijingTime 返回通知文案使用的北京时间。
func BeijingTime() string {
	return time.Now().In(chinaTimeZone).Format("2006-01-02 15:04:05")
}

// Message 是一条通知：正文为 Markdown，站内通知、邮件与 QQ 由同一份内容分别渲染。
// 来源二选一：SenderUserID 表示管理员发送，否则 AppID 表示应用发送（0 表示内置核心应用）。
type Message struct {
	AppID        int64
	SenderUserID int64
	Icon         string // Lucide 图标名，空值补为 DefaultIcon
	Title        string
	Desc         string
	Markdown     string
	Ext          map[string]any
}

// NewMessage 创建一条纯文本通知，每个 line 作为独立段落。
func NewMessage(title, desc string, lines ...string) Message {
	return Message{
		Title:    title,
		Desc:     desc,
		Markdown: strings.Join(lines, "\n\n"),
	}
}

// NewMarkdownMessage 创建一条 Markdown 通知，可指定结构化附加信息。
func NewMarkdownMessage(title, desc, markdown string, ext map[string]any) Message {
	return Message{
		Title:    title,
		Desc:     desc,
		Markdown: markdown,
		Ext:      ext,
	}
}

// ValidateMessage 校验并规范化通知内容，供接口层与服务层共用。
func ValidateMessage(msg *Message) *errs.Error {
	if msg == nil {
		return errs.BadRequestError().AppendDetails("通知内容为空")
	}

	if msg.AppID < 0 || msg.SenderUserID < 0 {
		return errs.BadRequestError().AppendDetails("通知来源格式错误")
	}
	if msg.AppID > 0 && msg.SenderUserID > 0 {
		return errs.BadRequestError().AppendDetails("通知来源应用与来源管理员不能同时设置")
	}

	msg.Icon = strings.TrimSpace(msg.Icon)
	if msg.Icon == "" {
		msg.Icon = DefaultIcon
	}
	if len(msg.Icon) > maxIconLen || !iconPattern.MatchString(msg.Icon) {
		return errs.BadRequestError().AppendDetails("通知图标格式错误，需为 Lucide 图标名（小写字母、数字与连字符）")
	}

	msg.Title = strings.TrimSpace(msg.Title)
	if msg.Title == "" {
		return errs.BadRequestError().AppendDetails("通知标题不能为空")
	}
	if utf8.RuneCountInString(msg.Title) > maxTitleRunes {
		return errs.BadRequestError().AppendDetails(fmt.Sprintf("通知标题不能超过 %d 个字符", maxTitleRunes))
	}

	if strings.TrimSpace(msg.Markdown) == "" {
		return errs.BadRequestError().AppendDetails("通知正文不能为空")
	}
	if len(msg.Markdown) > maxContentBytes {
		return errs.BadRequestError().AppendDetails(fmt.Sprintf("通知正文不能超过 %d KiB", maxContentBytes>>10))
	}

	if utf8.RuneCountInString(msg.Desc) > maxDescRunes {
		return errs.BadRequestError().AppendDetails(fmt.Sprintf("通知摘要不能超过 %d 个字符", maxDescRunes))
	}

	if msg.Ext != nil {
		ext, err := json.Marshal(msg.Ext)
		if err != nil {
			return errs.BadRequestError().AppendDetails("通知附加信息格式错误")
		}
		if len(ext) > maxExtBytes {
			return errs.BadRequestError().AppendDetails(fmt.Sprintf("通知附加信息不能超过 %d KiB", maxExtBytes>>10))
		}
	}

	return nil
}

func (m Message) html() string {
	return renderMarkdownHTML(m.Markdown)
}

func (m Message) text(sourceApp string) string {
	var b strings.Builder
	b.WriteString("【通知 - 复旦附中数字资源站】\n")
	b.WriteString("=====〖")
	b.WriteString(m.Title)
	b.WriteString("〗=====\n")
	if sourceApp != "" {
		b.WriteString("来源：")
		b.WriteString(sourceApp)
		b.WriteString("\n")
	}
	b.WriteString("\n")
	b.WriteString(renderMarkdownText(m.Markdown))
	b.WriteString("\n\n这是一条系统自动发送的通知，请勿直接回复。")
	return b.String()
}
