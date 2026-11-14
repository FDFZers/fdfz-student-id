package model

import (
	"time"

	"github.com/guregu/null/v6"
)

// PermissionDef 是一条权限定义。Value 是路径部分（如 users.list），补上所属应用的命名空间后
// 才是完整权限串（如 student_id:users.list）；同一应用下 (AppID, Value) 唯一。
type PermissionDef struct {
	ID          int64      `json:"id" db:"id"`
	AppID       int64      `json:"app_id" db:"app_id"`
	Value       string     `json:"value" db:"value"`
	Description string     `json:"description" db:"description"`
	Requestable bool       `json:"requestable" db:"requestable"` // OAuth 授权流程中是否允许应用申请
	CreatedBy   null.Int64 `json:"created_by" db:"created_by"`   // NULL 表示系统创建
	CreatedAt   time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at" db:"updated_at"`
}

// PermissionImply 是一条权限继承边：拥有 PermissionID 即隐含拥有 ImpliedPermissionID。
// 两条边必须属于同一个应用，由服务层与目录加载校验。
// GrantedByUserID 为 NULL 表示系统内置；ValidFrom/ValidUntil 为空表示不限制时间窗。
type PermissionImply struct {
	PermissionID        int64      `json:"permission_id" db:"permission_id"`
	ImpliedPermissionID int64      `json:"implied_permission_id" db:"implied_permission_id"`
	GrantedByUserID     null.Int64 `json:"granted_by_user_id" db:"granted_by_user_id"`
	ValidFrom           null.Time  `json:"valid_from" db:"valid_from"`
	ValidUntil          null.Time  `json:"valid_until" db:"valid_until"`
	Note                string     `json:"note" db:"note"`
	CreatedAt           time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at" db:"updated_at"`
}

// Role 是用户组（数据库表名 roles，API 与错误文案中统一称「用户组」）。
// 用户组属于某个应用；公开用户组允许其他应用引用与查看。
type Role struct {
	ID        int64     `json:"id" db:"id"`
	AppID     int64     `json:"app_id" db:"app_id"`
	Name      string    `json:"name" db:"name"`
	Note      string    `json:"note" db:"note"`
	Public    bool      `json:"public" db:"is_public"`
	System    bool      `json:"is_system" db:"is_system"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// RolePermission 是用户组权限模式，Permission 为完整权限模式（可能含 * / ** 通配）。
// GrantedByUserID 为 NULL 表示系统内置；ValidFrom/ValidUntil 为空表示不限制时间窗。
type RolePermission struct {
	RoleID          int64      `json:"role_id" db:"role_id"`
	Permission      string     `json:"permission" db:"permission"`
	GrantedByUserID null.Int64 `json:"granted_by_user_id" db:"granted_by_user_id"`
	ValidFrom       null.Time  `json:"valid_from" db:"valid_from"`
	ValidUntil      null.Time  `json:"valid_until" db:"valid_until"`
	Note            string     `json:"note" db:"note"`
	CreatedAt       time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at" db:"updated_at"`
}

// UserRole 表示用户被授予某个用户组，可带生效时间窗。
type UserRole struct {
	UserID     int64      `json:"user_id" db:"user_id"`
	RoleID     int64      `json:"role_id" db:"role_id"`
	GrantedBy  null.Int64 `json:"granted_by" db:"granted_by"`   // NULL 表示系统
	ValidFrom  null.Time  `json:"valid_from" db:"valid_from"`   // NULL 表示立即生效
	ValidUntil null.Time  `json:"valid_until" db:"valid_until"` // NULL 表示永不过期
	CreatedAt  time.Time  `json:"created_at" db:"created_at"`
}

// UserPermissionGrant 表示某个应用直接授予用户的权限（Permission 为完整权限串），可带生效时间窗。
// 同一用户同一权限只有一条记录，重复授权按覆盖处理。
type UserPermissionGrant struct {
	ID              int64      `json:"id" db:"id"`
	UserID          int64      `json:"user_id" db:"user_id"`
	Permission      string     `json:"permission" db:"permission"`                 // 完整权限串「命名空间:value」
	GrantedByUserID null.Int64 `json:"granted_by_user_id" db:"granted_by_user_id"` // NULL 表示系统
	GrantedByAppID  int64      `json:"granted_by_app_id" db:"granted_by_app_id"`   // 发起授权的应用
	ValidFrom       null.Time  `json:"valid_from" db:"valid_from"`                 // NULL 表示立即生效
	ValidUntil      null.Time  `json:"valid_until" db:"valid_until"`               // NULL 表示永不过期
	Note            string     `json:"note" db:"note"`
	CreatedAt       time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at" db:"updated_at"`
}
