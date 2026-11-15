package notify

import (
	"context"
	"html"
	"log/slog"
	"strconv"
	"strings"
	"time"

	usersvc "fdfz-student-id/internal/service/user"
)

// qqSendTimeout 是单次 QQ 通知发送的超时时间，避免 NapCat 异常时 goroutine 长期挂起。
const qqSendTimeout = 10 * time.Second

// chinaTimeZone 是通知文案中统一使用的北京时间。
var chinaTimeZone = time.FixedZone("CST", 8*60*60)

// BeijingTime 返回用于通知文案的北京时间，格式为 2006-01-02 15:04:05。
func BeijingTime() string {
	return time.Now().In(chinaTimeZone).Format("2006-01-02 15:04:05")
}

// Message 是一条账号安全通知；正文使用纯文本段落，渲染时再分别转换为邮件 HTML 与 QQ 文本。
type Message struct {
	Title string   // 通知标题，会同时用于邮件主题和 QQ 消息开头
	Desc  string   // 邮件预header摘要，仅邮件使用
	Lines []string // 正文段落，按纯文本处理
}

// NewMessage 创建一条通知文案。
func NewMessage(title, desc string, lines ...string) Message {
	return Message{Title: title, Desc: desc, Lines: lines}
}

// html 把正文转换为邮件 HTML，动态内容统一转义。
func (m Message) html() string {
	var b strings.Builder
	for _, line := range m.Lines {
		b.WriteString("<p>")
		b.WriteString(html.EscapeString(line))
		b.WriteString("</p>")
	}
	return b.String()
}

// text 把正文转换为 QQ 纯文本消息。
func (m Message) text() string {
	var b strings.Builder
	b.WriteString("【复旦附中学生 ID】\n")
	b.WriteString("=====[ ")
	b.WriteString(m.Title)
	b.WriteString(" ]=====\n")
	b.WriteString("\n")
	for _, line := range m.Lines {
		b.WriteString(line)
		b.WriteString("\n")
	}
	b.WriteString("\n这是一条系统自动发送的通知，请勿直接回复。")
	return b.String()
}

// Recipients 指定通知的收件目标；空字符串表示跳过对应渠道。
type Recipients struct {
	Email string
	QQ    string
}

// Send 向显式指定的邮箱与 QQ 异步发送通知，空目标直接跳过。
// 适用于绑定/解绑场景：需要额外通知刚刚绑定或刚刚解绑的渠道本身。
func Send(to Recipients, msg Message) {
	if to.Email != "" {
		sendEmail(to.Email, msg)
	}
	if to.QQ != "" {
		sendQQ(to.QQ, msg)
	}
}

// ToUser 向用户当前绑定的邮箱与 QQ 异步发送通知；未绑定的渠道自动跳过。
func ToUser(ctx context.Context, userID int64, msg Message) {
	var to Recipients

	if email, err := usersvc.GetUserEmail(ctx, userID); err != nil {
		slog.Warn("Failed to get user email for notification", "user_id", userID, "error", err.Info.Error)
	} else if email != nil {
		to.Email = email.Email
	}

	if qq, err := usersvc.GetUserQQ(ctx, userID); err != nil {
		slog.Warn("Failed to get user QQ for notification", "user_id", userID, "error", err.Info.Error)
	} else if qq != nil {
		to.QQ = qq.QQ
	}

	Send(to, msg)
}

// sendEmail 异步发送邮件通知；发送失败只记录日志。
func sendEmail(to string, msg Message) {
	go func() {
		if err := SendNotification(to, msg.Title, msg.Desc, msg.html()); err != nil {
			slog.Warn("Failed to send notification email", "to", to, "title", msg.Title, "error", err)
		}
	}()
}

// sendQQ 异步通过 NapCat 发送 QQ 私聊通知；发送失败只记录日志。
func sendQQ(qq string, msg Message) {
	go func() {
		userID, err := strconv.ParseInt(qq, 10, 64)
		if err != nil {
			slog.Warn("Failed to parse QQ for notification", "qq", qq, "error", err)
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), qqSendTimeout)
		defer cancel()

		if err := SendPrivateMessage(ctx, userID, msg.text()); err != nil {
			slog.Warn("Failed to send notification QQ message", "qq", qq, "title", msg.Title, "error", err)
		}
	}()
}
