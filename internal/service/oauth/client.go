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

// AuthenticateClient 校验客户端身份并返回应用。
// client_id 支持命名空间或数字 ID；confidential 客户端必须提供正确的 client_secret。
// 所有失败返回同一错误，避免暴露 client_id 是否存在。
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

// FindAppByClientID 按 client_id 查询应用：纯数字按 ID，其余按命名空间。
// 不存在或已删除时返回 (nil, nil)。
func FindAppByClientID(ctx context.Context, clientID string) (*model.OAuthApp, *errs.Error) {
	if id, err := strconv.ParseInt(clientID, 10, 64); err == nil && id > 0 {
		return appsvc.GetAppByID(ctx, id)
	}
	return appsvc.GetAppByNamespace(ctx, strings.TrimSpace(clientID))
}

// verifyClientSecret 用常量时间比较客户端密钥的 SHA-512 摘要。
func verifyClientSecret(app *model.OAuthApp, secret string) bool {
	if !app.SecretHash.Valid || app.SecretHash.String == "" {
		return false
	}
	sum := crypto.HashSHA512(secret)
	return subtle.ConstantTimeCompare([]byte(sum), []byte(app.SecretHash.String)) == 1
}
