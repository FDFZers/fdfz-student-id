//go:generate go tool go-enum --names --values --marshal --sql
package model

import (
	"time"

	"github.com/guregu/null/v6"
)

// AppType 应用类型：confidential/public 为普通 OAuth 客户端，*_device 为设备流客户端。
// ENUM(confidential, public, confidential_device, public_device)
type AppType string

// IsConfidential 判断该客户端类型是否需要客户端密钥（普通与设备流的 confidential 类型）。
func (t AppType) IsConfidential() bool {
	return t == AppTypeConfidential || t == AppTypeConfidentialDevice
}

// IsDevice 判断该客户端类型是否为设备流客户端（confidential_device 或 public_device）。
func (t AppType) IsDevice() bool {
	return t == AppTypeConfidentialDevice || t == AppTypePublicDevice
}

// AppStatus 应用状态：active 正常、suspended 已暂停。
// ENUM(active, suspended)
type AppStatus string

// AppAuthStatus 应用授权状态：active 已生效、pending 待确认。
// ENUM(active, pending)
type AppAuthStatus string

// OAuthApp OAuth 应用实体，对应 oauth_apps 表；应用同时是权限定义的命名空间所有者。
type OAuthApp struct {
	ID          int64       `json:"id" db:"id"`
	Namespace   string      `json:"namespace" db:"namespace"` // 权限命名空间，权限值形如 <namespace>:<nodes>，全站唯一
	OwnerUserID int64       `json:"owner_user_id" db:"owner_user_id"`
	SecretHash  null.String `json:"secret_hash" db:"secret_hash"` // 客户端密钥的 SHA-512 哈希；公开客户端为空

	Name           string   `json:"name" db:"name"`
	Description    string   `json:"description" db:"description"`
	HomepageURL    string   `json:"homepage_url" db:"homepage_url"`
	ClientType     AppType  `json:"client_type" db:"client_type"`         // 客户端类型，默认 confidential
	RedirectURIs   []string `json:"redirect_uris" db:"redirect_uris"`     // 允许的回调地址
	RequestedPerms []string `json:"requested_perms" db:"requested_perms"` // 应用申请的可授权权限

	Status AppStatus `json:"status" db:"status"` // 应用状态，默认 active

	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
	DeletedAt null.Time `json:"deleted_at" db:"deleted_at"` // 软删除时间，Valid 表示应用已删除
}

// OAuthAuthorization 用户对应用的授权记录；一个用户对一个应用至多一条。
type OAuthAuthorization struct {
	ID          int64         `json:"id" db:"id"`
	UserID      int64         `json:"user_id" db:"user_id"`
	AppID       int64         `json:"app_id" db:"app_id"`
	Permissions []string      `json:"permissions" db:"permissions"` // 用户授予应用的权限值
	Status      AppAuthStatus `json:"status" db:"status"`
	CreatedAt   time.Time     `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time     `json:"updated_at" db:"updated_at"`
	LastUsedAt  null.Time     `json:"last_used_at" db:"last_used_at"`
}

// OAuthRefreshToken OAuth 刷新令牌；只存令牌哈希，可轮换。
type OAuthRefreshToken struct {
	ID         int64     `json:"id" db:"id"`
	AuthID     int64     `json:"auth_id" db:"auth_id"` // 所属授权记录 ID
	TokenHash  string    `json:"token_hash" db:"token_hash"`
	CreatedAt  time.Time `json:"created_at" db:"created_at"`
	ExpiresAt  time.Time `json:"expires_at" db:"expires_at"`
	LastUsedAt null.Time `json:"last_used_at" db:"last_used_at"`
}
