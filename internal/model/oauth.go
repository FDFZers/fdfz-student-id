//go:generate go tool go-enum --names --values --marshal --sql
package model

import "time"

// ENUM(confidential, public, confidential_device, public_device)
type AppType string

// ENUM(active, suspended)
type AppStatus string

// ENUM(active, pending)
type AppAuthStatus string

type OAuthApp struct {
	ID             int64      `json:"id" db:"id"`
	Namespace      string     `json:"namespace" db:"namespace"`
	OwnerUserID    int64      `json:"owner_user_id" db:"owner_user_id"`
	SecretHash     *string    `json:"secret_hash" db:"secret_hash"`
	Name           string     `json:"name" db:"name"`
	Description    string     `json:"description" db:"description"`
	HomepageURL    string     `json:"homepage_url" db:"homepage_url"`
	ClientType     AppType    `json:"client_type" db:"client_type"`
	RedirectURIs   []string   `json:"redirect_uris" db:"redirect_uris"`
	RequestedPerms []string   `json:"requested_perms" db:"requested_perms"`
	Status         AppStatus  `json:"status" db:"status"`
	CreatedAt      time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at" db:"updated_at"`
	DeletedAt      *time.Time `json:"deleted_at" db:"deleted_at"`
}

type OAuthAuthorization struct {
	ID          int64         `json:"id" db:"id"`
	UserID      int64         `json:"user_id" db:"user_id"`
	AppID       int64         `json:"app_id" db:"app_id"`
	Permissions []string      `json:"permissions" db:"permissions"`
	Status      AppAuthStatus `json:"status" db:"status"`
	CreatedAt   time.Time     `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time     `json:"updated_at" db:"updated_at"`
	LastUsedAt  *time.Time    `json:"last_used_at" db:"last_used_at"`
}

type OAuthRefreshToken struct {
	ID         int64      `json:"id" db:"id"`
	AuthID     int64      `json:"auth_id" db:"auth_id"`
	TokenHash  string     `json:"token_hash" db:"token_hash"`
	CreatedAt  time.Time  `json:"created_at" db:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at" db:"expires_at"`
	LastUsedAt *time.Time `json:"last_used_at" db:"last_used_at"`
}
