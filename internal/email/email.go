package email

import (
	"embed"
	"fdfz-student-id/internal/cfg"
	"fdfz-student-id/internal/service/auth"
	"fmt"
	"log/slog"
	"mime"
	"net/smtp"
	"strings"
	"time"
)

//go:embed templates/*.html
var fs embed.FS

func send(to, subject, htmlBody string) error {
	auth := smtp.PlainAuth("", cfg.C.SMTP.Username, cfg.C.SMTP.Password, cfg.C.SMTP.Host)

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

	return smtp.SendMail(cfg.C.SMTP.Host+":"+cfg.C.SMTP.Port, auth, cfg.C.SMTP.From, []string{to}, []byte(msg.String()))
}

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
		slog.Info("Sending login verification code", "to", to, "code", code)
		r = strings.NewReplacer(
			"{{TITLE}}", "登录验证",
			"{{CODE_NAME}}", "登录验证码",
			"{{ACTION}}", "登录到复旦附中学生 ID",
			"{{ACTION_NOT_SELF}}", "忽略此邮件",
			"{{CODE}}", code,
		)
		title = "登录验证"
	case auth.AuthSessionTypeResetPassword:
		slog.Info("Sending password reset code", "to", to, "code", code)
		r = strings.NewReplacer(
			"{{TITLE}}", "密码重置",
			"{{CODE_NAME}}", "密码重置验证码",
			"{{ACTION}}", "重置复旦附中学生 ID 的密码",
			"{{ACTION_NOT_SELF}}", "忽略此邮件",
			"{{CODE}}", code,
		)
		title = "密码重置"
	case auth.AuthSessionTypeStepup:
		slog.Info("Sending stepup code", "to", to, "code", code)
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
