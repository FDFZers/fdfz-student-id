package notifications

import (
	"context"
	"log/slog"
	"slices"
	"strconv"
	"time"

	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	appsvc "fdfz-student-id/internal/service/app"
	usersvc "fdfz-student-id/internal/service/user"
)

// qqSendTimeout 是单次 QQ 通知发送的超时时间，避免 NapCat 异常时 goroutine 长期挂起。
const qqSendTimeout = 10 * time.Second

// Send 按所选渠道投递通知：站内通知同步写入数据库，邮件与 QQ 异步发送；站内写库失败时其余渠道可能已发出。
func Send(
	ctx context.Context,
	target Target,
	msg Message,
	channels []model.NotificationChannel,
) (*Result, *errs.Error) {
	if err := ValidateMessage(&msg); err != nil {
		return nil, err
	}
	if len(channels) == 0 {
		channels = DefaultChannels()
	}

	if !hasDeliverableTarget(target, channels) {
		return &Result{}, nil
	}

	source, err := resolveSource(ctx, msg.AppID, msg.SenderUserID)
	if err != nil {
		return nil, err
	}

	result := &Result{}
	for _, channel := range channels {
		switch channel {
		case model.NotificationChannelInapp:
			if target.UserID <= 0 {
				continue
			}
			notification, createErr := CreateInApp(ctx, target.UserID, source.source, msg)
			if createErr != nil {
				return nil, createErr
			}
			result.Notification = notification
		case model.NotificationChannelEmail:
			if target.Email == "" {
				continue
			}
			sendEmail(target.Email, msg, source.displayName)
		case model.NotificationChannelQQ:
			if target.QQ == "" {
				continue
			}
			sendQQ(target.QQ, msg, source.displayName)
		default:
			continue
		}
		result.Channels = append(result.Channels, channel)
	}

	return result, nil
}

// SendAsync 在后台执行 Send，剥离请求上下文的取消信号以免随请求返回中断，失败只记录日志。
func SendAsync(ctx context.Context, target Target, msg Message, channels []model.NotificationChannel) {
	ctx = context.WithoutCancel(ctx)
	go func() {
		if _, err := Send(ctx, target, msg, channels); err != nil {
			slog.Warn("Failed to send notification",
				"user_id", target.UserID,
				"title", msg.Title,
				"error", err.Info.Error,
				"details", err.Info.Details,
			)
		}
	}()
}

// ToUser 向用户当前绑定的全部渠道（站内、邮箱、QQ）异步发送通知；未绑定的渠道自动跳过。
func ToUser(ctx context.Context, userID int64, msg Message) {
	target := Target{UserID: userID}

	if email, err := usersvc.GetUserEmail(ctx, userID); err != nil {
		slog.Warn("Failed to get user email for notification", "user_id", userID, "error", err.Info.Error)
	} else if email != nil {
		target.Email = email.Email
	}

	if qq, err := usersvc.GetUserQQ(ctx, userID); err != nil {
		slog.Warn("Failed to get user QQ for notification", "user_id", userID, "error", err.Info.Error)
	} else if qq != nil {
		target.QQ = qq.QQ
	}

	SendAsync(ctx, target, msg, DefaultChannels())
}

// ResolveTarget 按所选渠道补全用户当前绑定的邮箱与 QQ；显式提供的地址优先。
func ResolveTarget(ctx context.Context, target Target, channels []model.NotificationChannel) (Target, *errs.Error) {
	if target.UserID <= 0 {
		return target, nil
	}

	needEmail := target.Email == "" && slices.Contains(channels, model.NotificationChannelEmail)
	needQQ := target.QQ == "" && slices.Contains(channels, model.NotificationChannelQQ)
	if !needEmail && !needQQ {
		return target, nil
	}

	if needEmail {
		email, err := usersvc.GetUserEmail(ctx, target.UserID)
		if err != nil {
			return target, err
		}
		if email != nil {
			target.Email = email.Email
		}
	}

	if needQQ {
		qq, err := usersvc.GetUserQQ(ctx, target.UserID)
		if err != nil {
			return target, err
		}
		if qq != nil {
			target.QQ = qq.QQ
		}
	}

	return target, nil
}

type resolvedSource struct {
	source      Source
	displayName string
}

func resolveSource(ctx context.Context, appID, senderUserID int64) (*resolvedSource, *errs.Error) {
	if senderUserID > 0 {
		sender, err := usersvc.GetUserByID(ctx, senderUserID)
		if err != nil {
			return nil, err
		}
		if sender == nil {
			return nil, errs.NotFoundError().AppendDetails("来源用户不存在")
		}
		return &resolvedSource{
			source:      Source{UserID: senderUserID},
			displayName: "管理员",
		}, nil
	}

	app, err := resolveSourceApp(ctx, appID)
	if err != nil {
		return nil, err
	}
	return &resolvedSource{
		source:      Source{App: app},
		displayName: app.Name,
	}, nil
}

// resolveSourceApp 解析通知来源应用：appID 为 0 时返回内置核心应用。
func resolveSourceApp(ctx context.Context, appID int64) (*model.OAuthApp, *errs.Error) {
	if appID > 0 {
		app, err := appsvc.GetAppByID(ctx, appID)
		if err != nil {
			return nil, err
		}
		if app == nil {
			return nil, errs.NotFoundError().AppendDetails("来源应用不存在")
		}
		return app, nil
	}

	app, err := appsvc.GetAppByNamespace(ctx, appsvc.CoreNamespace)
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, errs.InternalError().AppendDetails("核心应用不存在")
	}
	return app, nil
}

func hasDeliverableTarget(target Target, channels []model.NotificationChannel) bool {
	for _, channel := range channels {
		switch channel {
		case model.NotificationChannelInapp:
			if target.UserID > 0 {
				return true
			}
		case model.NotificationChannelEmail:
			if target.Email != "" {
				return true
			}
		case model.NotificationChannelQQ:
			if target.QQ != "" {
				return true
			}
		}
	}
	return false
}

// sendEmail 异步发送邮件通知；发送失败只记录日志。
func sendEmail(to string, msg Message, sourceApp string) {
	go func() {
		desc := msg.Desc
		if desc == "" {
			desc = msg.Title
		}
		if err := SendNotification(to, msg.Title, desc, sourceApp, msg.html()); err != nil {
			slog.Warn("Failed to send notification email", "to", to, "title", msg.Title, "error", err)
		}
	}()
}

// sendQQ 异步通过 NapCat 发送 QQ 私聊通知；发送失败只记录日志。
func sendQQ(qq string, msg Message, sourceApp string) {
	go func() {
		userID, err := strconv.ParseInt(qq, 10, 64)
		if err != nil {
			slog.Warn("Failed to parse QQ for notification", "qq", qq, "error", err)
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), qqSendTimeout)
		defer cancel()

		if err := SendPrivateMessage(ctx, userID, msg.text(sourceApp)); err != nil {
			slog.Warn("Failed to send notification QQ message", "qq", qq, "title", msg.Title, "error", err)
		}
	}()
}
