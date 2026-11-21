package oauth

import (
	"context"
	"crypto/subtle"
	"strconv"
	"strings"

	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	appsvc "fdfz-student-id/internal/service/app"
	"fdfz-student-id/internal/util/crypto"
)

// AuthenticateClient 校验客户端身份；认证失败统一返回同一错误，防止 client_id 枚举。
func AuthenticateClient(
	ctx context.Context,
	clientID string,
	clientSecret string,
) (*model.OAuthApp, *errs.Error) {
	if clientID == "" {
		return nil, errs.InvalidTokenError().AppendDetails("客户端认证失败").Seal()
	}

	app, err := FindAppByClientID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if app == nil || app.Status != model.AppStatusActive {
		return nil, errs.InvalidTokenError().AppendDetails("客户端认证失败").Seal()
	}

	if app.ClientType.IsConfidential() {
		if clientSecret == "" || !verifyClientSecret(app, clientSecret) {
			return nil, errs.InvalidTokenError().AppendDetails("客户端认证失败").Seal()
		}
	}
	return app, nil
}

func FindAppByClientID(ctx context.Context, clientID string) (*model.OAuthApp, *errs.Error) {
	if id, err := strconv.ParseInt(clientID, 10, 64); err == nil && id > 0 {
		return appsvc.GetAppByID(ctx, id)
	}
	return appsvc.GetAppByNamespace(ctx, strings.TrimSpace(clientID))
}

func verifyClientSecret(app *model.OAuthApp, secret string) bool {
	if !app.SecretHash.Valid || app.SecretHash.String == "" {
		return false
	}
	sum := crypto.HashSHA512(secret)
	return subtle.ConstantTimeCompare([]byte(sum), []byte(app.SecretHash.String)) == 1
}

// AppCanSendNotifications 返回应用是否具备发送通知的能力。
// 通知发送接口只接受客户端密钥认证，设备流客户端同样可以持有密钥。
func AppCanSendNotifications(app *model.OAuthApp) bool {
	return app != nil &&
		app.Status == model.AppStatusActive &&
		app.SecretHash.Valid &&
		app.SecretHash.String != ""
}

// AuthenticateClientWithSecret 强制校验客户端密钥，用于只接受服务端调用的接口。
func AuthenticateClientWithSecret(
	ctx context.Context,
	clientID string,
	clientSecret string,
) (*model.OAuthApp, *errs.Error) {
	if clientID == "" || clientSecret == "" {
		return nil, errs.InvalidTokenError().AppendDetails("客户端认证失败").Seal()
	}

	app, err := FindAppByClientID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if !AppCanSendNotifications(app) || !verifyClientSecret(app, clientSecret) {
		return nil, errs.InvalidTokenError().AppendDetails("客户端认证失败").Seal()
	}
	return app, nil
}
