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
