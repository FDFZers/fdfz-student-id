package notifications

import (
	"fmt"
	"strings"
	"time"

	"fdfz-student-id/internal/model"

	"github.com/guregu/null/v6"
)

func EscapeMarkdown(value string) string {
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	return markdownEscaper.Replace(value)
}

var markdownEscaper = strings.NewReplacer(
	`\`, `\\`,
	"`", "\\`",
	"*", "\\*",
	"_", "\\_",
	"{", "\\{",
	"}", "\\}",
	"[", "\\[",
	"]", "\\]",
	"(", "\\(",
	")", "\\)",
	"#", "\\#",
	"+", "\\+",
	"-", "\\-",
	".", "\\.",
	"!", "\\!",
	"|", "\\|",
	">", "\\>",
	"~", "\\~",
	"<", "\\<",
	"&", "\\&",
	"\"", "\\\"",
	"'", "\\'",
)

func FormatBeijingTime(t time.Time) string {
	return t.In(chinaTimeZone).Format("2006-01-02 15:04:05")
}

func newSecurityMessage(icon, title, desc, markdown string) Message {
	return Message{
		Icon:     icon,
		Title:    title,
		Desc:     desc,
		Markdown: markdown,
	}
}

func displayUserAgent(userAgent string) string {
	userAgent = strings.TrimSpace(userAgent)
	if userAgent == "" {
		return "未知"
	}
	runes := []rune(userAgent)
	if len(runes) > 180 {
		userAgent = string(runes[:180]) + "…"
	}
	return EscapeMarkdown(userAgent)
}

func displayIP(ip string) string {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return "未知"
	}
	return EscapeMarkdown(ip)
}

func displayAppName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "该应用"
	}
	return EscapeMarkdown(name)
}

func permissionBullets(permissions []string) string {
	if len(permissions) == 0 {
		return "- 无"
	}
	lines := make([]string, 0, len(permissions))
	for _, permission := range permissions {
		lines = append(lines, "- "+EscapeMarkdown(permission))
	}
	return strings.Join(lines, "\n")
}

func BooleanLabel(value bool, yes, no string) string {
	if value {
		return yes
	}
	return no
}

// ---------------------------------------------------------------------------
// 账号绑定与安全设置
// ---------------------------------------------------------------------------

func NewEmailBoundMessage(email string) Message {
	return newSecurityMessage("mail-check", "邮箱绑定成功", "你的账号已绑定新邮箱", fmt.Sprintf(
		"- **绑定时间**：%s (GMT+8)\n\n- **邮箱**：%s\n\n此后可使用该邮箱接收验证码、重置密码与账号通知。\n\n> 如非本人操作，请立即检查账号安全。",
		BeijingTime(), EscapeMarkdown(email),
	))
}

func NewEmailChangedMessage(oldEmail, newEmail string) Message {
	return newSecurityMessage("mail", "邮箱已更换", "你的账号已更换绑定邮箱", fmt.Sprintf(
		"- **变更时间**：%s (GMT+8)\n\n- **原邮箱**：%s\n- **新邮箱**：%s\n\n> 如非本人操作，请立即检查账号安全。",
		BeijingTime(), EscapeMarkdown(oldEmail), EscapeMarkdown(newEmail),
	))
}

func NewEmailUnboundMessage(email string) Message {
	return newSecurityMessage("mail-x", "邮箱已解绑", "你的账号已解绑邮箱", fmt.Sprintf(
		"- **解绑时间**：%s (GMT+8)\n\n- **邮箱**：%s\n\n解绑后将无法使用该邮箱接收验证码或重置密码。如非本人操作，请立即检查账号安全。",
		BeijingTime(), EscapeMarkdown(email),
	))
}

func NewQQBoundMessage(qq string) Message {
	return newSecurityMessage("message-circle-check", "QQ 已绑定", "你的账号已绑定 QQ", fmt.Sprintf(
		"- **绑定时间**：%s (GMT+8)\n\n- **QQ**：%s\n\n该 QQ 可用于登录验证与密码重置。如非本人操作，请立即检查账号安全。",
		BeijingTime(), EscapeMarkdown(qq),
	))
}

func NewQQUnboundMessage(qq string) Message {
	return newSecurityMessage("message-circle-x", "QQ 已解绑", "你的账号已解绑 QQ", fmt.Sprintf(
		"- **解绑时间**：%s (GMT+8)\n\n- **QQ**：%s\n\n解绑后该 QQ 将无法用于登录验证与密码重置。如非本人操作，请立即检查账号安全。",
		BeijingTime(), EscapeMarkdown(qq),
	))
}

func NewTOTPBoundMessage() Message {
	return newSecurityMessage("shield-check", "TOTP 已绑定", "你的账号已绑定 TOTP 二次验证", fmt.Sprintf(
		"- **绑定时间**：%s (GMT+8)\n\n- **验证方式**：TOTP 动态口令\n\n登录时将需要使用验证器应用生成的一次性验证码。\n\n> 如非本人操作，请立即检查账号安全。",
		BeijingTime(),
	))
}

func NewTOTPUnboundMessage() Message {
	return newSecurityMessage("shield-off", "TOTP 已解绑", "你的账号已解绑 TOTP 二次验证", fmt.Sprintf(
		"- **解绑时间**：%s (GMT+8)\n\n- **验证方式**：TOTP 动态口令\n\n解绑后将不再支持 TOTP 二次验证，账号安全性可能降低。\n\n> 如非本人操作，请立即检查账号安全。",
		BeijingTime(),
	))
}

func NewTwoFactorEnabledMessage() Message {
	return newSecurityMessage("shield-check", "登录二次验证已开启", "你的账号已开启登录二次验证", fmt.Sprintf(
		"- **操作时间**：%s (GMT+8)\n\n- **登录二次验证**：已开启\n\n之后登录时需要使用已绑定的邮箱、QQ 或 TOTP 完成二次验证。\n\n> 如非本人操作，请立即检查账号安全。",
		BeijingTime(),
	))
}

func NewTwoFactorDisabledMessage() Message {
	return newSecurityMessage("shield-off", "登录二次验证已关闭", "你的账号已关闭登录二次验证", fmt.Sprintf(
		"- **操作时间**：%s (GMT+8)\n\n- **登录二次验证**：已关闭\n\n关闭后登录只需密码；修改密码、绑定方式与会话管理等敏感操作仍要求二次验证。\n\n> 如非本人操作，请立即检查账号安全。",
		BeijingTime(),
	))
}

// ---------------------------------------------------------------------------
// 密码
// ---------------------------------------------------------------------------

func NewPasswordChangedMessage() Message {
	return newSecurityMessage("key-round", "密码已修改", "你的账号密码已修改", fmt.Sprintf(
		"- **操作时间**：%s (GMT+8)\n\n- **操作内容**：修改登录密码\n\n如非本人操作，请立即检查账号安全。",
		BeijingTime(),
	))
}

func NewPasswordResetMessage() Message {
	return newSecurityMessage("key-round", "密码已重置", "你的账号密码已重置", fmt.Sprintf(
		"- **操作时间**：%s (GMT+8)\n\n- **操作内容**：通过忘记密码重置登录密码\n\n所有登录会话已退出，请使用新密码重新登录。\n\n> 如非本人操作，请立即检查账号安全。",
		BeijingTime(),
	))
}

func NewPasswordResetAtLoginMessage() Message {
	return newSecurityMessage("key-round", "密码已重设", "你的账号密码已在登录时重设", fmt.Sprintf(
		"- **操作时间**：%s (GMT+8)\n\n- **操作内容**：在登录时重设登录密码\n\n如非本人操作，请立即检查账号安全。",
		BeijingTime(),
	))
}

func NewAdminPasswordResetMessage(requireReset bool) Message {
	nextStep := "下次登录时可继续使用新密码。"
	if requireReset {
		nextStep = "下次登录时需要先设置新密码。"
	}
	return newSecurityMessage("key-round", "密码已被管理员重置", "你的账号密码已被管理员重置", fmt.Sprintf(
		"- **操作时间**：%s (GMT+8)\n\n- **操作内容**：管理员重置了你的登录密码\n\n%s\n\n> 如非本人操作，请立即检查账号安全。",
		BeijingTime(), nextStep,
	))
}

// ---------------------------------------------------------------------------
// 账号与登录
// ---------------------------------------------------------------------------

func NewAccountDeletionScheduledMessage(scheduledAt time.Time) Message {
	return newSecurityMessage("user-x", "账号注销申请已提交", "你的账号将在 7 天后注销", fmt.Sprintf(
		"- **提交时间**：%s (GMT+8)\n\n- **计划删除**：%s (GMT+8)\n- **冷静期**：7 天\n\n冷静期内重新登录可取消注销；到期后将删除账号及关联数据。\n\n> 如非本人操作，请立即检查账号安全。",
		BeijingTime(), FormatBeijingTime(scheduledAt),
	))
}

func NewAccountDeletionCancelledMessage() Message {
	return newSecurityMessage("rotate-ccw", "账号注销已取消", "你的账号注销申请已取消", fmt.Sprintf(
		"- **取消时间**：%s (GMT+8)\n\n- **账号注销**：已取消\n\n你在冷静期内重新登录，账号注销申请已自动取消。如需继续注销，请重新提交申请。",
		BeijingTime(),
	))
}

// NewLoginMessage 登录成功提醒；每次登录 finalize 都会发送。
func NewLoginMessage(ip, userAgent string, temporary bool) Message {
	return newSecurityMessage("monitor-smartphone", "登录提醒", "你的账号刚刚登录", fmt.Sprintf(
		"- **登录时间**：%s (GMT+8)\n\n- **IP 地址**：%s\n- **设备**：%s\n- **会话类型**：%s\n\n> 如非本人操作，请立即检查账号安全。",
		BeijingTime(), displayIP(ip), displayUserAgent(userAgent), BooleanLabel(temporary, "临时会话", "常规会话"),
	))
}

// ---------------------------------------------------------------------------
// OAuth 授权与会话
// ---------------------------------------------------------------------------

func NewOAuthAuthorizedMessage(appName string, permissions []string, allowNotifications bool) Message {
	return newSecurityMessage("app-window", "应用授权提醒", "你的账号授权了新应用", fmt.Sprintf(
		"- **应用**：%s\n\n- **授权时间**：%s (GMT+8)\n- **通知权限**：%s\n\n授予的权限：\n\n%s\n\n> 如非本人操作，请立即检查账号安全。",
		displayAppName(appName), BeijingTime(), BooleanLabel(allowNotifications, "已允许", "未允许"), permissionBullets(permissions),
	))
}

func NewOAuthDeviceAuthorizedMessage(appName string, permissions []string, allowNotifications bool) Message {
	return newSecurityMessage("monitor-smartphone", "设备授权提醒", "你的账号通过设备码授权了应用", fmt.Sprintf(
		"- **应用**：%s\n\n- **授权时间**：%s (GMT+8)\n- **授权方式**：设备码\n- **通知权限**：%s\n\n授予的权限：\n\n%s\n\n> 如非本人操作，请立即检查账号安全。",
		displayAppName(appName), BeijingTime(), BooleanLabel(allowNotifications, "已允许", "未允许"), permissionBullets(permissions),
	))
}

func NewOAuthAuthorizationRevokedMessage(appName string) Message {
	return newSecurityMessage("shield-off", "应用授权已撤销", "你的账号已撤销应用授权", fmt.Sprintf(
		"- **应用**：%s\n\n- **撤销时间**：%s (GMT+8)\n\n该应用已无法继续使用你的账号授权；如需要，请重新授权。",
		displayAppName(appName), BeijingTime(),
	))
}

func NewSessionsRevokedMessage() Message {
	return newSecurityMessage("log-out", "登录会话已退出", "你的账号已退出全部登录会话", fmt.Sprintf(
		"- **操作时间**：%s (GMT+8)\n\n- **操作范围**：全部登录会话\n\n你账号的所有登录会话已被退出。已签发的访问令牌会在过期前继续有效。\n\n> 如非本人操作，请立即检查账号安全。",
		BeijingTime(),
	))
}

func NewSessionRevokedMessage(session *model.UserSession) Message {
	ip := ""
	if session != nil && session.LastIP != nil {
		ip = *session.LastIP
	}
	userAgent := ""
	createdAt := time.Now()
	if session != nil {
		userAgent = session.LastUserAgent
		createdAt = session.CreatedAt
	}
	return newSecurityMessage("log-out", "登录会话已退出", "你的账号退出了一条登录会话", fmt.Sprintf(
		"- **操作时间**：%s (GMT+8)\n\n- **会话创建**：%s (GMT+8)\n- **IP 地址**：%s\n- **设备**：%s\n\n该登录会话已被退出。已签发的访问令牌会在过期前继续有效。\n\n> 如非本人操作，请立即检查账号安全。",
		BeijingTime(), FormatBeijingTime(createdAt), displayIP(ip), displayUserAgent(userAgent),
	))
}

func NewAppNotificationsSettingMessage(enabled bool) Message {
	detail := "关闭后，任何应用都不能再向你发送通知；平台自身的安全通知不受影响。"
	if enabled {
		detail = "重新开启后，已获授权的应用可以继续向你发送通知。"
	}
	return newSecurityMessage(
		BooleanLabel(enabled, "bell", "bell-off"),
		"应用通知已"+BooleanLabel(enabled, "开启", "关闭"),
		"你的应用通知设置已变更",
		fmt.Sprintf(
			"- **操作时间**：%s (GMT+8)\n\n- **应用通知**：%s\n\n%s",
			BeijingTime(), BooleanLabel(enabled, "已开启", "已关闭"), detail,
		),
	)
}

func NewUserBannedMessage(reason string, endTime null.Time) Message {
	endLabel := "永久封禁"
	if endTime.Valid {
		endLabel = "北京时间 " + FormatBeijingTime(endTime.Time)
	}
	return newSecurityMessage("ban", "账号已被封禁", "你的账号已被封禁", fmt.Sprintf(
		"- **操作时间**：%s (GMT+8)\n\n- **处理结果**：账号已被封禁\n- **封禁原因**：%s\n- **解封时间**：%s\n\n封禁期间将无法登录。如对处理有异议，请联系管理员。",
		BeijingTime(), EscapeMarkdown(reason), endLabel,
	))
}

func NewUserUnbannedMessage() Message {
	return newSecurityMessage("circle-check", "账号封禁已解除", "你的账号封禁已解除", fmt.Sprintf(
		"- **操作时间**：%s (GMT+8)\n\n- **处理结果**：账号封禁已解除\n\n你现在可以正常登录与使用账号。",
		BeijingTime(),
	))
}
