//go:generate go tool go-enum --names --values --marshal --sql
package model

import "time"

// ENUM(confidential, public)
type OAuthClientType string

type OAuthApp struct {
	ID          int64  `json:"id" db:"id"`
	Namespace   string `json:"namespace" db:"namespace"`
	OwnerUserID int64  `json:"owner_user_id" db:"owner_user_id"`
	SecretHash  string `json:"secret_hash" db:"secret_hash"`

	Name        string `json:"name" db:"name"`
	Description string `json:"description" db:"description"`

	ClientType           OAuthClientType `json:"client_type" db:"client_type"`
	RedirectURIs         []string        `json:"redirect_uris" db:"redirect_uris"`
	RequestedPermissions []string        `json:"requested_permissions" db:"requested_permissions"`

	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt time.Time  `json:"updated_at" db:"updated_at"`
	DeletedAt *time.Time `json:"deleted_at" db:"deleted_at"`
}

type UserOAuthApp struct {
	ID          int64      `json:"id" db:"id"`
	UserID      int64      `json:"user_id" db:"user_id"`
	AppID       int64      `json:"app_id" db:"app_id"`
	Permissions []string   `json:"permissions" db:"permissions"`
	UpdatedAt   time.Time  `json:"updated_at" db:"updated_at"`
	RevokedAt   *time.Time `json:"revoked_at" db:"revoked_at"`
}
