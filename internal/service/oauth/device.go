package oauth

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"fdfz-student-id/internal/cfg"
	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	appsvc "fdfz-student-id/internal/service/app"
	"fdfz-student-id/internal/util/crypto"
	"fdfz-student-id/internal/util/handling"
	"fdfz-student-id/internal/util/slicex"
)

const (
	devicePollIntervalSeconds = 5
	deviceCodeInsertAttempts  = 5
)

type DeviceAuthorization struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int64  `json:"expires_in"`
	Interval        int32  `json:"interval"`
}

type DevicePreview struct {
	App         *handling.AppInfo           `json:"app"`
	UserCode    string                      `json:"user_code"`
	Permissions []PermissionInfo            `json:"permissions"`
	Status      model.OAuthDeviceCodeStatus `json:"status"`
	ExpiresAt   time.Time                   `json:"expires_at"`
}

// DeviceTokenResponse 的 status 为 pending/denied/expired/approved；仅 approved 携带令牌，轮询过快返回 429。
type DeviceTokenResponse struct {
	Status       string   `json:"status"`
	AccessToken  string   `json:"access_token,omitempty"`
	TokenType    string   `json:"token_type,omitempty"`
	ExpiresIn    int64    `json:"expires_in,omitempty"`
	RefreshToken string   `json:"refresh_token,omitempty"`
	Permissions  []string `json:"permissions,omitempty"`
}

// ---------------------------------------------------------------------------
// 发起
// ---------------------------------------------------------------------------

// StartDeviceAuthorization 仅适用于 *_device 类型；permission 为空时使用应用登记的全部可申请权限。
func StartDeviceAuthorization(
	ctx context.Context,
	client *model.OAuthApp,
	permissionParam string,
) (*DeviceAuthorization, *errs.Error) {
	if !client.ClientType.IsDevice() {
		return nil, errs.BadRequestError().AppendDetails("该应用不支持设备授权流程")
	}

	permissions, err := ResolveRequestedPermissions(client, permissionParam)
	if err != nil {
		return nil, err
	}

	ttl := cfg.C.OAuthDeviceCodeTTL
	expiresAt := time.Now().Add(ttl).UnixMilli()

	var (
		deviceCode string
		userCode   string
	)
	for attempt := 0; attempt < deviceCodeInsertAttempts; attempt++ {
		rawDeviceCode, e := crypto.GenerateCode(64, crypto.TokenCharset)
		if e != nil {
			return nil, errs.CreateAndLogInternalError(e, "Failed to generate oauth device code").AppendDetails("设备码生成失败")
		}
		rawUserCode, e := crypto.GenerateCode(8, crypto.CodeCharset)
		if e != nil {
			return nil, errs.CreateAndLogInternalError(e, "Failed to generate oauth user code").AppendDetails("用户码生成失败")
		}

		candidate := rawUserCode[:4] + "-" + rawUserCode[4:]
		record := &deviceCodeRecord{
			UserCode:        candidate,
			AppID:           client.ID,
			Permissions:     permissions,
			Status:          model.OAuthDeviceCodeStatusPending,
			IntervalSeconds: devicePollIntervalSeconds,
			ExpiresAt:       expiresAt,
		}
		stored, err := tryStoreDeviceCode(ctx, rawDeviceCode, record, ttl)
		if err != nil {
			return nil, err
		}
		if stored {
			deviceCode, userCode = rawDeviceCode, candidate
			break
		}
	}
	if deviceCode == "" {
		return nil, errs.CreateAndLogInternalError(errors.New("device code conflict"), "Failed to allocate oauth device code").AppendDetails("设备码生成失败")
	}

	baseURI := verificationURI()
	return &DeviceAuthorization{
		DeviceCode:      deviceCode,
		UserCode:        userCode,
		VerificationURI: baseURI,
		ExpiresIn:       ttlSeconds(ttl),
		Interval:        devicePollIntervalSeconds,
	}, nil
}

// ---------------------------------------------------------------------------
// 确认页
// ---------------------------------------------------------------------------

// GetDeviceAuthorization 返回设备授权详情；Granted 按当前用户有效权限计算。
func GetDeviceAuthorization(
	ctx context.Context,
	userID int64,
	userCode string,
) (*DevicePreview, *errs.Error) {
	normalized := NormalizeUserCode(userCode)
	if normalized == "" {
		return nil, errs.BadRequestError().AppendDetails("user_code 格式错误")
	}

	record, _, err := getDeviceCodeByUserCode(ctx, normalized)
	if err != nil {
		return nil, err
	}
	if record == nil || time.Now().UnixMilli() >= record.ExpiresAt {
		return nil, errs.NotFoundError().AppendDetails("设备授权请求不存在或已过期")
	}

	app, err := appsvc.GetAppByID(ctx, record.AppID)
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, errs.NotFoundError().AppendDetails("应用不存在")
	}
	if app.Status != model.AppStatusActive {
		return nil, errs.NotFoundError().AppendDetails("应用已停用")
	}

	infos, err := ResolvePermissionInfos(ctx, userID, record.Permissions)
	if err != nil {
		return nil, err
	}

	return &DevicePreview{
		App:         handling.AppJSON(app),
		UserCode:    record.UserCode,
		Permissions: infos,
		Status:      record.Status,
		ExpiresAt:   time.UnixMilli(record.ExpiresAt),
	}, nil
}

// DecideDeviceAuthorization 通过 Lua 脚本原子更新状态，只允许从 pending 迁移；permissions 非 nil 时按子集收窄。
func DecideDeviceAuthorization(
	ctx context.Context,
	userID int64,
	userCode string,
	approve bool,
	permissions []string,
) *errs.Error {
	normalized := NormalizeUserCode(userCode)
	if normalized == "" {
		return errs.BadRequestError().AppendDetails("user_code 格式错误")
	}

	record, deviceHash, err := getDeviceCodeByUserCode(ctx, normalized)
	if err != nil {
		return err
	}
	if record == nil || time.Now().UnixMilli() >= record.ExpiresAt {
		return errs.NotFoundError().AppendDetails("设备授权请求不存在或已过期")
	}
	if record.Status != model.OAuthDeviceCodeStatusPending {
		return errs.IllegalStateError().AppendDetails("该设备授权请求已处理")
	}

	app, err := appsvc.GetAppByID(ctx, record.AppID)
	if err != nil {
		return err
	}
	if app == nil {
		return errs.NotFoundError().AppendDetails("应用不存在")
	}
	if app.Status != model.AppStatusActive {
		return errs.IllegalStateError().AppendDetails("应用已停用")
	}

	if !approve {
		result, err := decideDeviceCode(ctx, deviceHash, model.OAuthDeviceCodeStatusDenied, 0, userID)
		if err != nil {
			return err
		}
		return deviceDecisionResult(result)
	}
	// 发起后应用可能修改申请权限，旧确认请求必须作废。
	if err := ValidatePermissionsAgainstApp(app, record.Permissions); err != nil {
		return errs.ConflictError().AppendDetails("应用申请权限已变更，请重新发起设备授权")
	}

	infos, err := ResolvePermissionInfos(ctx, userID, record.Permissions)
	if err != nil {
		return err
	}
	granted := GrantedPermissions(infos)

	if permissions != nil {
		selected := slicex.DedupeStrings(permissions)
		for _, permission := range selected {
			if !slices.Contains(record.Permissions, permission) {
				return errs.BadRequestError().AppendDetails("提交的权限不在本次申请范围内")
			}
		}
		granted = restrictToRequested(granted, selected)
	}

	// 先写授权记录再更新设备码状态；状态更新失败最多留下一条多余授权，不会越权。
	authID, err := upsertAuthorization(ctx, userID, record.AppID, granted)
	if err != nil {
		return err
	}

	result, err := decideDeviceCode(ctx, deviceHash, model.OAuthDeviceCodeStatusApproved, authID, userID)
	if err != nil {
		return err
	}
	return deviceDecisionResult(result)
}

func deviceDecisionResult(result int64) *errs.Error {
	switch result {
	case 1:
		return nil
	case -1:
		return errs.NotFoundError().AppendDetails("设备授权请求不存在或已过期")
	default:
		return errs.IllegalStateError().AppendDetails("该设备授权请求已处理")
	}
}

// ---------------------------------------------------------------------------
// 轮询
// ---------------------------------------------------------------------------

// ExchangeDeviceCode 轮询设备码；已批准的设备码在脚本内即被删除，保证只能换一次令牌。
func ExchangeDeviceCode(
	ctx context.Context,
	client *model.OAuthApp,
	deviceCode string,
) (*DeviceTokenResponse, *errs.Error) {
	if deviceCode == "" {
		return nil, errs.BadRequestError().AppendDetails("缺少设备码")
	}

	envelope, err := pollDeviceCode(ctx, deviceCode, client.ID)
	if err != nil {
		return nil, err
	}

	switch envelope.Status {
	case "pending":
		return &DeviceTokenResponse{Status: "pending"}, nil
	case "too_fast":
		return nil, errs.RateLimitExceededError().AppendDetails("轮询频率过快")
	case "denied":
		return &DeviceTokenResponse{Status: "denied"}, nil
	case "missing", "invalid", "expired":
		return &DeviceTokenResponse{Status: "expired"}, nil
	case "approved":
	default:
		return nil, errs.CreateAndLogInternalError(
			errors.New("unexpected device poll status: "+envelope.Status),
			"Unexpected oauth device poll status",
		)
	}

	record := envelope.Record
	if record == nil {
		return nil, errs.CreateAndLogInternalError(errors.New("approved device code missing record"), "Approved oauth device code missing record")
	}
	if record.AppID != client.ID || record.AuthID == 0 || record.UserID == 0 {
		return nil, errs.CreateAndLogInternalError(errors.New("inconsistent approved device code"), "Inconsistent approved oauth device code")
	}

	state, err := loadAuthorizationForToken(ctx, db.R, record.AuthID, record.AppID, record.UserID)
	if err != nil {
		return nil, err
	}
	if state == nil {
		return nil, errs.BadRequestError().AppendDetails("授权记录不存在")
	}
	if state.AuthStatus != model.AppAuthStatusActive ||
		state.AppStatus != model.AppStatusActive || state.UserDeletedAt.Valid {
		return nil, errs.BadRequestError().AppendDetails("授权已失效")
	}

	permissions, err := effectiveGrantPermissions(ctx, record.UserID, state.Permissions)
	if err != nil {
		return nil, err
	}

	refreshToken, refreshTokenHash, e := newRefreshToken()
	if e != nil {
		return nil, errs.CreateAndLogInternalError(e, "Failed to generate oauth refresh token").AppendDetails("令牌生成失败")
	}

	// 设备码已被消费，签发失败只能重新发起授权。
	accessToken, expiresIn, e := issueAccessToken(record.UserID, record.AppID, record.AuthID, permissions)
	if e != nil {
		return nil, errs.CreateAndLogInternalError(e, "Failed to issue oauth access token").AppendDetails("令牌生成失败")
	}

	if err := touchAuthorization(ctx, db.R, record.AuthID); err != nil {
		return nil, err
	}
	if err := insertRefreshToken(ctx, db.R, record.AuthID, refreshTokenHash, time.Now().Add(cfg.C.OAuthRefreshTokenTTL)); err != nil {
		return nil, err
	}

	return &DeviceTokenResponse{
		Status:       "approved",
		AccessToken:  accessToken,
		ExpiresIn:    expiresIn,
		RefreshToken: refreshToken,
		Permissions:  permissions,
	}, nil
}

// ---------------------------------------------------------------------------
// 工具
// ---------------------------------------------------------------------------

func NormalizeUserCode(raw string) string {
	var builder strings.Builder
	for _, r := range strings.ToUpper(strings.TrimSpace(raw)) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			builder.WriteRune(r)
		}
	}
	code := builder.String()
	if len(code) != 8 {
		return ""
	}
	return code[:4] + "-" + code[4:]
}

func verificationURI() string {
	return strings.TrimRight(cfg.C.AuthFrontendURL, "/") + "/oauth"
}
