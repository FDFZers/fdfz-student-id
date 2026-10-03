package model

import "time"

type PermissionInfo struct {
	ID          int64     `json:"id" db:"id"`
	AppID       int64     `json:"app_id" db:"app_id"`
	Value       string    `json:"value" db:"value"`
	Description string    `json:"description" db:"description"`
	Parents     []int64   `json:"parents" db:"parents"` // 父权限，递归包含这些权限
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

type UserPermission struct {
	ID         int64      `json:"id" db:"id"`
	UserID     int64      `json:"user_id" db:"user_id"`
	Permission string     `json:"permission" db:"permission"`
	Enabled    bool       `json:"enabled" db:"enabled"`
	ValidFrom  *time.Time `json:"valid_from" db:"valid_from"`
	ValidUntil *time.Time `json:"valid_until" db:"valid_until"`
	CreatedAt  time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at" db:"updated_at"`
	Note       string     `json:"note" db:"note"`
}
