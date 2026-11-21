package notifications

import (
	"embed"
	"fdfz-student-id/internal/cfg"
	authsvc "fdfz-student-id/internal/service/auth"
	"fmt"
	"html"
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

// SMTP 的 MAIL FROM 只接受裸地址，发件人显示名需先解析，否则会被服务器拒绝。
func envelopeFrom(from string) string {
	if addr, err := mail.ParseAddress(from); err == nil {
		return addr.Address
	}
	return from
}

// isBackupSMTPRecipient 判断收件人域名是否在 SMTP_BACKUP_DOMAINS 配置中。
func isBackupSMTPRecipient(address string) bool {
	parsed, err := mail.ParseAddress(address)
	if err != nil {
		return false
	}
	at := strings.LastIndexByte(parsed.Address, '@')
	if at < 0 {
		return false
	}
	domain := strings.ToLower(parsed.Address[at+1:])
	for _, backupDomain := range cfg.C.SMTPBackupDomains {
		if strings.EqualFold(domain, backupDomain) {
			return true
		}
	}
	return false
}

// smtpConfigForRecipient 选择收件人对应的 SMTP 配置；未配置备用服务时回退主服务。
func smtpConfigForRecipient(to string) (cfg.SMTPConfig, bool) {
	if cfg.C.SMTPBackup.Host != "" && isBackupSMTPRecipient(to) {
		return cfg.C.SMTPBackup, true
	}
	return cfg.C.SMTP, false
}

// send 组装 MIME 邮件并通过主/备用 SMTP 配置发送。
// 收件人域名在 SMTP_BACKUP_DOMAINS 中时优先使用备用 SMTP（若已配置）；主题按 RFC 2047 编码。
func send(to, subject, htmlBody string) error {
	smtpCfg, usingBackup := smtpConfigForRecipient(to)
	if usingBackup {
		slog.Info("Using backup SMTP", "to", to, "host", smtpCfg.Host)
	}

	a := smtp.PlainAuth("", smtpCfg.Username, smtpCfg.Password, smtpCfg.Host)

	encodedSubject := mime.BEncoding.Encode("UTF-8", subject)

	msg := strings.Builder{}
	msg.WriteString("From: " + smtpCfg.From + "\r\n")
	msg.WriteString("To: " + to + "\r\n")
	msg.WriteString("Subject: " + encodedSubject + "\r\n")
	msg.WriteString("Date: " + time.Now().Format(time.RFC1123Z) + "\r\n")
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	msg.WriteString("\r\n")
	msg.WriteString(htmlBody)

	return smtp.SendMail(smtpCfg.Host+":"+smtpCfg.Port, a, envelopeFrom(smtpCfg.From), []string{to}, []byte(msg.String()))
}

// SendCode 按鉴权会话类型选择文案，渲染验证码模板并发送。
// 注意：typ 必须是登录、重置密码或二次验证之一，其他取值返回错误。
func SendCode(to, code string, typ authsvc.AuthSessionType) error {
	data, err := fs.ReadFile("templates/code.html")
	if err != nil {
		return err
	}
	str := string(data)
	var r *strings.Replacer
	var title string
	switch typ {
	case authsvc.AuthSessionTypeLogin:
		slog.Info("Sending login verification code", "to", to)
		r = strings.NewReplacer(
			"{{TITLE}}", "登录验证",
			"{{CODE_NAME}}", "登录验证码",
			"{{ACTION}}", "登录到复旦附中学生 ID",
			"{{ACTION_NOT_SELF}}", "忽略此邮件",
			"{{CODE}}", code,
		)
		title = "登录验证"
	case authsvc.AuthSessionTypeResetPassword:
		slog.Info("Sending password reset code", "to", to)
		r = strings.NewReplacer(
			"{{TITLE}}", "密码重置",
			"{{CODE_NAME}}", "密码重置验证码",
			"{{ACTION}}", "重置复旦附中学生 ID 的密码",
			"{{ACTION_NOT_SELF}}", "忽略此邮件",
			"{{CODE}}", code,
		)
		title = "密码重置"
	case authsvc.AuthSessionTypeStepup:
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

func renderNotificationEmail(title, desc, sourceApp, body string) (string, error) {
	data, err := fs.ReadFile("templates/notif.html")
	if err != nil {
		return "", err
	}
	r := strings.NewReplacer(
		"{{TITLE}}", html.EscapeString(title),
		"{{DESC}}", html.EscapeString(desc),
		"{{APP}}", html.EscapeString(sourceApp),
		"{{BODY}}", body,
	)
	return r.Replace(string(data)), nil
}

// SendNotification 渲染并发送通知邮件；body 直接写入 HTML，调用方需保证其可信（包内由 Markdown 渲染器生成）。
func SendNotification(to, title, desc, sourceApp, body string) error {
	htmlBody, err := renderNotificationEmail(title, desc, sourceApp, body)
	if err != nil {
		return err
	}
	slog.Info("Sending notification email", "to", to, "title", title, "source_app", sourceApp)
	return send(to, title+" - 复旦附中数字资源站", htmlBody)
}
