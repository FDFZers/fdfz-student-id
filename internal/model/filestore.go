//go:generate go tool go-enum --names --values --marshal --sql
package model

import (
	"time"

	"github.com/guregu/null/v6"
)

// FileTokenType 文件令牌类型：upload 上传、download 下载。
// ENUM(upload, download)
type FileTokenType string

// FileMetadata 文件元数据，文件内容由对象存储按 SHA-512 去重保存。
type FileMetadata struct {
	ID          int64      `json:"id"`
	Slug        string     `json:"slug"`         // 对外访问路径中的短标识
	SHA512      string     `json:"sha512"`       // 文件内容哈希，用于去重与完整性校验
	Filename    string     `json:"filename"`     // 原始文件名，用于下载时的 Content-Disposition
	Description string     `json:"description"`  // 文件描述，展示用
	ContentType string     `json:"content_type"` // MIME 类型
	UserID      null.Int64 `json:"user_id"`      // 上传用户 ID，匿名为空
	AppID       null.Int64 `json:"app_id"`       // 上传应用 ID，用户上传为空
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// FileBan 文件封禁记录，命中后拒绝下载。
type FileBan struct {
	ID       int64      `json:"id"`
	FileID   int64      `json:"file_id"`
	UserID   null.Int64 `json:"user_id"` // 执行封禁的操作者用户 ID
	Comment  string     `json:"comment"` // 封禁原因
	BannedAt time.Time  `json:"banned_at"`
}
