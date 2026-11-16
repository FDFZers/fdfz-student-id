package oauth

import (
	"context"
	"net/url"
	"slices"
	"time"

	"fdfz-student-id/internal/cfg"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	appsvc "fdfz-student-id/internal/service/app"
	"fdfz-student-id/internal/util/crypto"
	"fdfz-student-id/internal/util/handling"

	"github.com/google/uuid"
)

const (
	maxStateLength = 512
)

// ---------------------------------------------------------------------------
// 授权请求
// ---------------------------------------------------------------------------

// AuthorizationParams 是授权请求参数，不要求 response_type 等协议字段；权限固定取自应用登记值。
type AuthorizationParams struct {
	ClientID      string
	RedirectURI   string
	State         string
	CodeChallenge string // 可选，提供时按 SHA-512 校验
}

// ConsentRequest 是暂存在 Redis 的确认请求，回调地址、code_challenge 与 state 以服务端记录为准。
type ConsentRequest struct {
	ID                  string    `json:"id"`
	UserID              int64     `json:"user_id"`
	AppID               int64     `json:"app_id"`
	RedirectURI         string    `json:"redirect_uri"`
	RedirectURIProvided bool      `json:"redirect_uri_provided"`
	State               string    `json:"state"`
	Permissions         []string  `json:"permissions"`
	CodeChallenge       string    `json:"code_challenge"`
	CreatedAt           time.Time `json:"created_at"`
}

type AuthorizationPreview struct {
	RequestID         string            `json:"request_id"`
	ExpiresIn         int64             `json:"expires_in"`
	App               *handling.AppInfo `json:"app"`
	RedirectURI       string            `json:"redirect_uri"`
	State             string            `json:"state"`
	Permissions       []PermissionInfo  `json:"permissions"`
	AlreadyAuthorized bool              `json:"already_authorized"`
}

// ---------------------------------------------------------------------------
// 预览
// ---------------------------------------------------------------------------

// PreviewAuthorization 返回授权确认页预览，并把确认请求写入 Redis。
func PreviewAuthorization(
	ctx context.Context,
	userID int64,
	params AuthorizationParams,
) (*AuthorizationPreview, *errs.Error) {
	app, err := FindAppByClientID(ctx, params.ClientID)
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, errs.BadRequestError().AppendDetails("应用不存在")
	}
	if app.Status != model.AppStatusActive {
		return nil, errs.IllegalStateError().AppendDetails("应用已停用")
	}
	if app.ClientType.IsDevice() {
		return nil, errs.BadRequestError().AppendDetails("该应用仅支持设备授权流程")
	}

	redirectURI, err := resolveRedirectURI(app, params.RedirectURI)
	if err != nil {
		return nil, err
	}

	if len(params.State) > maxStateLength {
		return nil, errs.BadRequestError().AppendDetails("state 参数过长")
	}

	permissions, err := ResolveRequestedPermissions(app)
	if err != nil {
		return nil, err
	}

	if !crypto.ValidCodeChallenge(params.CodeChallenge) {
		return nil, errs.BadRequestError().AppendDetails("code_challenge 格式错误")
	}
	if !app.ClientType.IsConfidential() && params.CodeChallenge == "" {
		return nil, errs.BadRequestError().AppendDetails("公开客户端必须使用 PKCE（code_challenge）")
	}

	infos, err := ResolvePermissionInfos(ctx, userID, permissions)
	if err != nil {
		return nil, err
	}

	// 已有覆盖全部可授予权限的有效授权时，前端可跳过确认页。
	existing, err := getAuthorizationByUserApp(ctx, userID, app.ID)
	if err != nil {
		return nil, err
	}
	alreadyAuthorized := false
	if existing != nil && existing.Status == model.AppAuthStatusActive {
		granted := GrantedPermissions(infos)
		alreadyAuthorized = len(granted) > 0
		for _, permission := range granted {
			if !slices.Contains(existing.Permissions, permission) {
				alreadyAuthorized = false
				break
			}
		}
	}

	request := &ConsentRequest{
		ID:                  uuid.NewString(),
		UserID:              userID,
		AppID:               app.ID,
		RedirectURI:         redirectURI,
		RedirectURIProvided: params.RedirectURI != "",
		State:               params.State,
		Permissions:         permissions,
		CodeChallenge:       params.CodeChallenge,
		CreatedAt:           time.Now(),
	}
	if err := SaveConsentRequest(ctx, request); err != nil {
		return nil, err
	}

	return &AuthorizationPreview{
		RequestID:         request.ID,
		ExpiresIn:         int64(cfg.C.OAuthConsentRequestTTL / time.Second),
		App:               handling.AppJSON(app),
		RedirectURI:       redirectURI,
		State:             params.State,
		Permissions:       infos,
		AlreadyAuthorized: alreadyAuthorized,
	}, nil
}

// ---------------------------------------------------------------------------
// 确认
// ---------------------------------------------------------------------------

// ApproveAuthorization 处理同意/拒绝并返回客户端回调地址；授予应用登记的全部可授予权限。
func ApproveAuthorization(
	ctx context.Context,
	userID int64,
	requestID string,
	approve bool,
) (string, *errs.Error) {
	request, err := TakeConsentRequest(ctx, requestID)
	if err != nil {
		return "", err
	}
	if request == nil {
		return "", errs.NotFoundError().AppendDetails("授权请求不存在或已过期")
	}
	if request.UserID != userID {
		return "", errs.PermissionDeniedError().AppendDetails("授权请求不属于当前用户").Seal()
	}

	app, err := appsvc.GetAppByID(ctx, request.AppID)
	if err != nil {
		return "", err
	}
	if app == nil {
		return "", errs.NotFoundError().AppendDetails("应用不存在")
	}
	if app.Status != model.AppStatusActive {
		return "", errs.IllegalStateError().AppendDetails("应用已停用")
	}
	if err := ValidatePermissionsAgainstApp(app, request.Permissions); err != nil {
		return "", errs.ConflictError().AppendDetails("应用申请权限已变更，请重新授权")
	}
	if !app.ClientType.IsConfidential() && request.CodeChallenge == "" {
		return "", errs.ConflictError().AppendDetails("应用已改为公开客户端，请使用 PKCE 重新授权")
	}
	if resolved, e := resolveRedirectURI(app, request.RedirectURI); e != nil || resolved != request.RedirectURI {
		return "", errs.ConflictError().AppendDetails("应用回调地址已变更，请重新授权")
	}

	if !approve {
		return buildRedirectURL(request.RedirectURI, url.Values{
			"error":             {"access_denied"},
			"error_description": {"用户拒绝了授权"},
			"state":             {request.State},
		})
	}

	infos, err := ResolvePermissionInfos(ctx, userID, request.Permissions)
	if err != nil {
		return "", err
	}
	granted := GrantedPermissions(infos)

	code, err := createAuthorizationAndCode(ctx, request, granted)
	if err != nil {
		return "", err
	}

	return buildRedirectURL(request.RedirectURI, url.Values{
		"code":  {code},
		"state": {request.State},
	})
}

// createAuthorizationAndCode 更新授权并写入一次性授权码，授权码只保存 SHA-512 哈希。
func createAuthorizationAndCode(
	ctx context.Context,
	request *ConsentRequest,
	permissions []string,
) (string, *errs.Error) {
	if permissions == nil {
		permissions = []string{}
	}

	authID, err := upsertAuthorization(ctx, request.UserID, request.AppID, permissions)
	if err != nil {
		return "", err
	}

	code, err := storeAuthorizationCode(ctx, &authorizationCode{
		AppID:               request.AppID,
		AuthID:              authID,
		UserID:              request.UserID,
		RedirectURI:         request.RedirectURI,
		RedirectURIProvided: request.RedirectURIProvided,
		CodeChallenge:       request.CodeChallenge,
		ExpiresAt:           time.Now().Add(cfg.C.OAuthCodeTTL),
	})
	if err != nil {
		return "", err
	}
	return code, nil
}

// ---------------------------------------------------------------------------
// 回调地址
// ---------------------------------------------------------------------------

// resolveRedirectURI 校验回调地址与应用登记值完全一致。
func resolveRedirectURI(app *model.OAuthApp, requested string) (string, *errs.Error) {
	if requested == "" {
		switch len(app.RedirectURIs) {
		case 0:
			return "", errs.BadRequestError().AppendDetails("应用未配置回调地址")
		case 1:
			return app.RedirectURIs[0], nil
		default:
			return "", errs.BadRequestError().AppendDetails("缺少 redirect_uri")
		}
	}
	if !slices.Contains(app.RedirectURIs, requested) {
		return "", errs.BadRequestError().AppendDetails("redirect_uri 未在应用登记的回调地址中")
	}
	return requested, nil
}

// buildRedirectURL 在回调地址上合并查询参数；回调地址不含 fragment，直接覆盖 RawQuery。
func buildRedirectURL(base string, values url.Values) (string, *errs.Error) {
	parsed, err := url.Parse(base)
	if err != nil {
		return "", errs.CreateAndLogInternalError(err, "Failed to parse oauth redirect uri").AppendDetails("回调地址格式错误")
	}
	query := parsed.Query()
	for key, items := range values {
		for _, item := range items {
			if item == "" {
				continue
			}
			query.Set(key, item)
		}
	}
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}
