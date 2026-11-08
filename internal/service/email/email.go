// Package email 通过 SMTP 发送 HTML 验证码邮件，支持登录/重置密码/二次验证与邮箱绑定场景。
package email

import (
	"embed"
	"fdfz-student-id/internal/cfg"
	"fdfz-student-id/internal/service/auth"
	"fmt"
	"log/slog"
	"mime"
	"net/mail"
	"net/smtp"
	"strings"
	"time"
)

// fs 内嵌 templates 目录下的 HTML 邮件模板。
//
//go:embed templates/*.html
var fs embed.FS

// envelopeFrom 从 SMTP_FROM 中提取信封发件人地址。
// SMTP 的 MAIL FROM 只接受裸地址（RFC 5321），而 SMTP_FROM 允许带显示名
// （如 "FDFZ Bot <noreply@fdfz.top>"），直接把显示名交给 smtp.SendMail 会被服务器以语法错误拒绝。
func envelopeFrom(from string) string {
	if addr, err := mail.ParseAddress(from); err == nil {
		return addr.Address
	}
	return from
}

// send 组装 MIME 邮件并通过 SMTP_* 配置发送。
// 主题按 RFC 2047 编码，正文为 HTML；发送失败时返回底层错误。
func send(to, subject, htmlBody string) error {
	a := smtp.PlainAuth("", cfg.C.SMTP.Username, cfg.C.SMTP.Password, cfg.C.SMTP.Host)

	encodedSubject := mime.BEncoding.Encode("UTF-8", subject)

	msg := strings.Builder{}
	msg.WriteString("From: " + cfg.C.SMTP.From + "\r\n")
	msg.WriteString("To: " + to + "\r\n")
	msg.WriteString("Subject: " + encodedSubject + "\r\n")
	msg.WriteString("Date: " + time.Now().Format(time.RFC1123Z) + "\r\n")
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	msg.WriteString("\r\n")
	msg.WriteString(htmlBody)

	return smtp.SendMail(cfg.C.SMTP.Host+":"+cfg.C.SMTP.Port, a, envelopeFrom(cfg.C.SMTP.From), []string{to}, []byte(msg.String()))
}

// SendCode 按鉴权会话类型选择文案，渲染验证码模板并发送。
// 注意：typ 必须是登录、重置密码或二次验证之一，其他取值返回错误。
func SendCode(to, code string, typ auth.AuthSessionType) error {
	data, err := fs.ReadFile("templates/code.html")
	if err != nil {
		return err
	}
	str := string(data)
	var r *strings.Replacer
	var title string
	switch typ {
	case auth.AuthSessionTypeLogin:
		slog.Info("Sending login verification code", "to", to)
		r = strings.NewReplacer(
			"{{TITLE}}", "登录验证",
			"{{CODE_NAME}}", "登录验证码",
			"{{ACTION}}", "登录到复旦附中学生 ID",
			"{{ACTION_NOT_SELF}}", "忽略此邮件",
			"{{CODE}}", code,
		)
		title = "登录验证"
	case auth.AuthSessionTypeResetPassword:
		slog.Info("Sending password reset code", "to", to)
		r = strings.NewReplacer(
			"{{TITLE}}", "密码重置",
			"{{CODE_NAME}}", "密码重置验证码",
			"{{ACTION}}", "重置复旦附中学生 ID 的密码",
			"{{ACTION_NOT_SELF}}", "忽略此邮件",
			"{{CODE}}", code,
		)
		title = "密码重置"
	case auth.AuthSessionTypeStepup:
		slog.Info("Sending stepup code", "to", to)
		r = strings.NewReplacer(
			"{{TITLE}}", "二次验证",
			"{{CODE_NAME}}", "二次验证码",
			"{{ACTION}}", "进行二次验证以执行危险操作",
			"{{ACTION_NOT_SELF}}", "请立即检查你的账号安全",
			"{{CODE}}", code,
		)
		title = "二次验证"
	default:
		return fmt.Errorf("unknown auth session type: %v", typ)
	}
	return send(to, title+" - 复旦附中学生 ID", r.Replace(str))
}

// SendBindEmailCode 发送邮箱绑定验证码邮件。
func SendBindEmailCode(to, code string) error {
	data, err := fs.ReadFile("templates/code.html")
	if err != nil {
		return err
	}
	r := strings.NewReplacer(
		"{{TITLE}}", "邮箱绑定",
		"{{CODE_NAME}}", "邮箱绑定验证码",
		"{{ACTION}}", "绑定邮箱到复旦附中学生 ID",
		"{{ACTION_NOT_SELF}}", "请立即检查你的账号安全",
		"{{CODE}}", code,
	)
	slog.Info("Sending email binding code", "to", to)
	return send(to, "邮箱绑定 - 复旦附中学生 ID", r.Replace(string(data)))
}
