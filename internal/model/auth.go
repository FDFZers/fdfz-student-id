//go:generate go tool go-enum --names --values --marshal --sql
package model

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/guregu/null/v6"
)

// ENUM(pending, approved, rejected)
type RegisterRequestStatus string

// ENUM(argon2id, bcrypt)
type PasswordAlgorithm string

// ENUM(user, oauth)
type TokenType string

type RegisterRequest struct {
	ID int64 `json:"id" db:"id"`

	Type       UserType    `json:"type" db:"type"`
	StudentNum null.String `json:"student_num" db:"student_num"`
	RealName   string      `json:"real_name" db:"real_name"`
	School     School      `json:"school" db:"school"`

	Username string `json:"username" db:"username"`
	Password string `json:"password" db:"password"`

	CreatedAt      time.Time             `json:"created_at" db:"created_at"`
	Status         RegisterRequestStatus `json:"status" db:"status"`
	ReviewerUserID *int64                `json:"reviewer_user_id" db:"reviewer_user_id"`
	ReviewedAt     *time.Time            `json:"reviewed_at" db:"reviewed_at"`
}

type UserPassword struct {
	UserID    int64             `json:"user_id" db:"user_id"`
	Password  string            `json:"password" db:"password"`
	Algorithm PasswordAlgorithm `json:"algorithm" db:"algorithm"`
	UpdatedAt time.Time         `json:"updated_at" db:"updated_at"`
}

type UserTotp struct {
	UserID    int64     `json:"user_id" db:"user_id"`
	Secret    string    `json:"secret" db:"secret"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

type UserSession struct {
	UUID   uuid.UUID `json:"uuid" db:"uuid"`
	UserID int64     `json:"user_id" db:"user_id"`

	SessionTokenHash string `json:"session_token_hash" db:"session_token_hash"`

	CreatedAt  time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at" db:"updated_at"`
	ExpiresAt  time.Time  `json:"expires_at" db:"expires_at"`
	LastUsedAt *time.Time `json:"last_used_at" db:"last_used_at"`
	RevokedAt  *time.Time `json:"revoked_at" db:"revoked_at"`

	LastIP        *string `json:"last_ip" db:"last_ip"`
	LastUserAgent string  `json:"last_user_agent" db:"last_user_agent"`
}

type TokenClaims struct {
	UserID      int64       `json:"user_id" db:"user_id"`
	TokenType   TokenType   `json:"token_type" db:"token_type"`
	AppID       null.String `json:"app_id" db:"app_id"`
	Permissions []string    `json:"permissions" db:"permissions"`
}

type RegisteredTokenClaims struct {
	TokenClaims
	jwt.RegisteredClaims
}
