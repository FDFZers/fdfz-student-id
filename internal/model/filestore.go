//go:generate go tool go-enum --names --values --marshal --sql
package model

import (
	"time"

	"github.com/guregu/null/v6"
)

// ENUM(upload, download)
type FileTokenType string

type FileMetadata struct {
	ID          int64      `json:"id"`
	Slug        string     `json:"slug"`
	SHA512      string     `json:"sha512"`
	Filename    string     `json:"filename"`
	Description string     `json:"description"`
	ContentType string     `json:"content_type"`
	UserID      null.Int64 `json:"user_id"`
	AppID       null.Int64 `json:"app_id"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

type FileBan struct {
	ID       int64      `json:"id"`
	FileID   int64      `json:"file_id"`
	UserID   null.Int64 `json:"user_id"`
	Comment  string     `json:"comment"`
	BannedAt time.Time  `json:"banned_at"`
}
