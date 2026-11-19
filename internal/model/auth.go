//go:generate go tool go-enum --names --values --marshal --sql
package model

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/guregu/null/v6"
)

// RegisterRequestStatus 注册申请审核状态：pending 待审核、approved 已通过、rejected 已驳回。
// ENUM(pending, approved, rejected)
type RegisterRequestStatus string

// TokenType 令牌类型：user 用户访问令牌、stepup 提权令牌、OAuth 应用令牌。
// ENUM(user, stepup, OAuth = "oauth")
type TokenType string

// RegisterRequest 注册申请记录，审核通过后据此创建用户。
type RegisterRequest struct {
	ID uuid.UUID `json:"id" db:"id"`

	Type       UserType    `json:"type" db:"type"`               // 申请的用户类型
	StudentNum null.String `json:"student_num" db:"student_num"` // 学号，仅学生类型有值
	RealName   string      `json:"real_name" db:"real_name"`     // 真实姓名
	School     School      `json:"school" db:"school"`           // 所属学校

	Username string      `json:"username" db:"username"` // 申请的用户名
	Nickname null.String `json:"nickname" db:"nickname"` // 昵称，可空
	Password string      `json:"password" db:"password"` // argon2id 密码哈希，提交注册时即完成哈希

	CreatedAt      time.Time             `json:"created_at" db:"created_at"`             // 申请提交时间
	Status         RegisterRequestStatus `json:"status" db:"status"`                     // 审核状态，默认 pending
	CreatedUserID  *int64                `json:"created_user_id" db:"created_user_id"`   // 审核通过后创建的用户 ID，未创建时为空
	ReviewerUserID *int64                `json:"reviewer_user_id" db:"reviewer_user_id"` // 审核人用户 ID
	ReviewComment  *string               `json:"review_comment" db:"review_comment"`     // 审核意见
	ReviewedAt     *time.Time            `json:"reviewed_at" db:"reviewed_at"`           // 审核完成时间
}

// UserPassword 用户密码，与用户一对一；改密时整行覆盖，不保留旧哈希。
type UserPassword struct {
	UserID    int64     `json:"user_id" db:"user_id"`
	Password  string    `json:"password" db:"password"` // argon2id 编码串
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// UserTOTP TOTP 二次验证密钥，与用户一对一；只存共享密钥，不存生成过的验证码。
type UserTOTP struct {
	UserID    int64     `json:"user_id" db:"user_id"`
	Secret    string    `json:"secret" db:"secret"` // Base32 编码的共享密钥，明文存储
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// UserSession 登录会话记录，一个用户可有多条；会话令牌只存哈希，撤销用 RevokedAt 标记而不删除。
type UserSession struct {
	UUID   uuid.UUID `json:"uuid" db:"uuid"` // 会话 ID，同时作为访问令牌的 JWT ID
	UserID int64     `json:"user_id" db:"user_id"`

	SessionTokenHash string `json:"session_token_hash" db:"session_token_hash"` // 会话令牌的 SHA-512 哈希
	IsTemporary      bool   `json:"is_temporary" db:"is_temporary"`             // 临时会话，刷新时不延长有效期

	CreatedAt  time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at" db:"updated_at"`
	ExpiresAt  time.Time  `json:"expires_at" db:"expires_at"`
	LastUsedAt *time.Time `json:"last_used_at" db:"last_used_at"` // 最近一次刷新令牌的时间
	RevokedAt  *time.Time `json:"revoked_at" db:"revoked_at"`     // 非空表示已撤销或已注销

	LastIP        *string `json:"last_ip" db:"last_ip"`                 // 最近一次使用的 IP，可空
	LastUserAgent string  `json:"last_user_agent" db:"last_user_agent"` // 最近一次使用的 User-Agent
}

// TokenClaims JWT 自定义声明，用户访问令牌、提权令牌与 OAuth 应用令牌共用。
// 注意：为避免 JWT（进而 Set-Cookie）体积随权限数量膨胀，令牌内只保存权限 ID，
// 具体权限串与应用所有者信息由 /api/internal/auth/claims 接口另行提供。
type TokenClaims struct {
	UserID      int64       `json:"user_id"`
	TokenType   TokenType   `json:"token_type"`            // 令牌类型，决定其可访问的接口
	Permissions []int64     `json:"permissions"`           // 已解析权限的 ID，升序去重，如 [3,7]
	AppID       null.String `json:"app_id,omitzero"`       // 【OAuth 令牌】所属应用 ID
	AuthID      null.Int    `json:"auth_id,omitzero"`      // 【OAuth 令牌】对应的授权记录 ID
	SessionID   null.String `json:"session_id,omitzero"`   // 【提权令牌】绑定的登录会话 UUID
	IsTemporary bool        `json:"is_temporary,omitzero"` // 【用户令牌】是否为临时会话
}

// RegisteredTokenClaims jwt 标准声明与 TokenClaims 的组合，用于签发与解析 JWT。
type RegisteredTokenClaims struct {
	TokenClaims
	jwt.RegisteredClaims
}
