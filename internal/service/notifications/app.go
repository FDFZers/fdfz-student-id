package notifications

import (
	"context"

	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	oauthsvc "fdfz-student-id/internal/service/oauth"
)

// SendFromApp 供第三方应用发送通知，先校验授权与总开关，再强制来源应用为 app。
// channels 为空时只投递站内通知，不默认触发邮件或 QQ。
func SendFromApp(
	ctx context.Context,
	app *model.OAuthApp,
	userID int64,
	msg Message,
	channels []model.NotificationChannel,
) (*Result, *errs.Error) {
	if app == nil {
		return nil, errs.BadRequestError().AppendDetails("应用不存在")
	}
	if !oauthsvc.AppCanSendNotifications(app) {
		return nil, errs.IllegalStateError().AppendDetails("应用未配置客户端密钥").Seal()
	}
	if userID <= 0 {
		return nil, errs.BadRequestError().AppendDetails("用户 ID 格式错误")
	}
	if len(channels) == 0 {
		channels = []model.NotificationChannel{model.NotificationChannelInapp}
	}

	allowed, err := oauthsvc.UserAllowsAppNotifications(ctx, userID, app.ID)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, errs.PermissionDeniedError().
			AppendDetails("用户未允许该应用发送通知，或已关闭应用通知").
			Seal()
	}

	msg.AppID = app.ID
	msg.SenderUserID = 0
	target, err := ResolveTarget(ctx, Target{UserID: userID}, channels)
	if err != nil {
		return nil, err
	}
	return Send(ctx, target, msg, channels)
}
