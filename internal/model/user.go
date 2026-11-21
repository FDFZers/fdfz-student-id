//go:generate go tool go-enum --names --values --marshal --sql
package model

import (
	"time"

	"github.com/guregu/null/v6"
)

// UserType 用户类型：student 学生、teacher 老师。
// ENUM(student, teacher)
type UserType string

// School 学校；数据库中同时作为学生学号唯一性的作用域。
// ENUM(FDFZ = fdfz,FFXH = ffxh,FFQP = ffqp,FFPD = ffpd, FFJA = ffja)
type School string

// Visibility 资料可见性：public 公开、friends 好友可见、private 仅自己。
// ENUM(public, friends, private)
type Visibility string

// Visibilities 用户资料各字段的可见性设置，对应 users.visibilities JSONB 列。
type Visibilities struct {
	RealName  Visibility `json:"real_name"` // 真实姓名可见性
	Followers Visibility `json:"followers"` // 粉丝列表可见性
	Following Visibility `json:"following"` // 关注列表可见性
}

// Normalize 将未设置的可见性统一为 private，供资料写入与展示前调用。
func (v *Visibilities) Normalize() {
	if v.RealName == "" {
		v.RealName = VisibilityPrivate
	}
	if v.Followers == "" {
		v.Followers = VisibilityPrivate
	}
	if v.Following == "" {
		v.Following = VisibilityPrivate
	}
}

// User 用户实体，对应 users 表。
// 注意：DeletedAt 非空即为软删除（注销），记录仍保留供外键与历史数据引用。
type User struct {
	ID       int64  `json:"id" db:"id"`
	Username string `json:"username" db:"username"`

	Type       UserType    `json:"type" db:"type"`               // 用户类型，默认 student
	StudentNum null.String `json:"student_num" db:"student_num"` // 学号，仅学生类型有值
	RealName   string      `json:"real_name" db:"real_name"`
	School     School      `json:"school" db:"school"` // 所属学校，默认 fdfz

	Nickname  null.String `json:"nickname" db:"nickname"` // 昵称，可空
	Signature string      `json:"signature" db:"signature"`
	Bio       string      `json:"bio" db:"bio"`

	Visibilities Visibilities `json:"visibilities" db:"visibilities"` // 资料可见性，JSONB 列

	// PasswordResetRequired 表示管理员创建账号或重置密码后，用户下次登录应重设密码。
	PasswordResetRequired bool `json:"password_reset_required" db:"password_reset_required"`

	// TwoFactorEnabled 表示登录时是否要求二次验证；关闭后登录只需密码，
	// 但修改密码、绑定方式、会话管理等敏感操作仍要求二次验证。
	TwoFactorEnabled bool `json:"two_factor_enabled" db:"two_factor_enabled"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
	DeletedAt null.Time `json:"deleted_at" db:"deleted_at"` // 软删除时间，非空表示已注销
}

// UserBan 用户封禁记录；同一用户可有多条历史，仅 enabled 的一条为当前生效封禁。
type UserBan struct {
	ID        int64     `json:"id" db:"id"`
	UserID    int64     `json:"user_id" db:"user_id"`
	Reason    string    `json:"reason" db:"reason"`
	EndTime   null.Time `json:"end_time" db:"end_time"` // 解封时间，NULL 表示永久封禁
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	Enabled   bool      `json:"enabled" db:"enabled"` // 是否生效；解封或到期后置 false
}

// UserEmail 用户邮箱，与用户一对一；换绑/解绑走软删除以保留历史记录。
type UserEmail struct {
	ID        int64     `json:"id" db:"id"`
	UserID    int64     `json:"user_id" db:"user_id"`
	Email     string    `json:"email" db:"email"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	DeletedAt null.Time `json:"deleted_at" db:"deleted_at"` // 非空表示已解绑或随账号注销删除
}

// UserQQ 用户绑定的 QQ 号，与用户一对一；换绑/解绑走软删除以保留历史记录。
type UserQQ struct {
	ID        int64     `json:"id" db:"id"`
	UserID    int64     `json:"user_id" db:"user_id"`
	QQ        string    `json:"qq" db:"qq"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	DeletedAt null.Time `json:"deleted_at" db:"deleted_at"` // 非空表示已解绑或随账号注销删除
}
