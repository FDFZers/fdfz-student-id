package model

import "github.com/guregu/null/v6"

type StoreFileReq struct {
	Slug         string      `json:"slug,omitempty"`
	FilePath     string      `json:"file_path,omitempty"`
	FileName     string      `json:"file_name,omitempty"`
	ContentType  null.String `json:"content_type"`
	SHA512       null.String `json:"sha512"`
	IsPrivate    bool        `json:"is_private"`
	ShouldUpsert bool        `json:"should_upsert"`
	ShouldCopy   bool        `json:"should_copy"`
	UserID       null.Int64  `json:"user_id"`
	AppID        null.Int64  `json:"app_id"`
	BanComment   null.String `json:"ban_comment"`
}
