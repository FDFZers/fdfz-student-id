package model

import (
	"time"

	"github.com/guregu/null/v6"
)

type PermissionDef struct {
	ID          int64      `json:"id" db:"id"`
	AppID       int64      `json:"app_id" db:"app_id"`
	Value       string     `json:"value" db:"value"`
	Description string     `json:"description" db:"description"`
	Requestable bool       `json:"requestable" db:"requestable"`
	CreatedBy   null.Int64 `json:"created_by" db:"created_by"`
	CreatedAt   time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at" db:"updated_at"`
}

type PermissionImply struct {
	PermissionID        int64 `json:"permission_id" db:"permission_id"`
	ImpliedPermissionID int64 `json:"implied_permission_id" db:"implied_permission_id"`
}

type Role struct {
	ID        int64     `json:"id" db:"id"`
	AppID     int64     `json:"app_id" db:"app_id"`
	Name      string    `json:"name" db:"name"`
	Note      string    `json:"note" db:"note"`
	Public    bool      `json:"public" db:"is_public"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

type RolePermission struct {
	RoleID       int64 `json:"role_id" db:"role_id"`
	PermissionID int64 `json:"permission_id" db:"permission_id"`
}

type UserRole struct {
	UserID     int64      `json:"user_id" db:"user_id"`
	RoleID     int64      `json:"role_id" db:"role_id"`
	GrantedBy  null.Int64 `json:"granted_by" db:"granted_by"` // NULL 表示系统
	ValidFrom  null.Time  `json:"valid_from" db:"valid_from"`
	ValidUntil null.Time  `json:"valid_until" db:"valid_until"`
	CreatedAt  time.Time  `json:"created_at" db:"created_at"`
}

type UserPermissionGrant struct {
	ID              int64      `json:"id" db:"id"`
	UserID          int64      `json:"user_id" db:"user_id"`
	Permission      string     `json:"permission" db:"permission"`
	GrantedByUserID null.Int64 `json:"granted_by_user_id" db:"granted_by_user_id"` // NULL 表示系统
	GrantedByAppID  int64      `json:"granted_by_app_id" db:"granted_by_app_id"`
	ValidFrom       null.Time  `json:"valid_from" db:"valid_from"`
	ValidUntil      null.Time  `json:"valid_until" db:"valid_until"`
	Note            string     `json:"note" db:"note"`
	CreatedAt       time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at" db:"updated_at"`
}
