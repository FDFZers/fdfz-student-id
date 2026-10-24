package filestore

import (
	"bytes"
	"encoding/json"
	"errors"
	"fdfz-student-id/internal/cfg"
	"fdfz-student-id/internal/errs"
	fileutils "fdfz-student-id/internal/util/file"
	"fdfz-student-id/internal/util/storage"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"

	"github.com/guregu/null/v6"
)

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

func UploadFile(fileHeader *multipart.FileHeader, request *StoreFileReq) *errs.Error {
	rel, dst, err := storage.UploadTempPath()
	if err != nil {
		return errs.InternalError().AppendDetails("临时文件路径获取失败")
	}
	tempWriter, err := fileutils.NewTempWriter(dst, nil)
	if err != nil {
		return errs.InternalError().AppendDetails("临时文件创建失败")
	}

	file, err := fileHeader.Open()
	if err != nil {
		return errs.InternalError().AppendDetails("请求体文件打开失败")
	}
	defer func(file multipart.File) {
		err := file.Close()
		if err != nil {
			slog.Warn("Failed to close file", "error", err)
		}
	}(file)

	if _, err := tempWriter.WriteFrom(file); err != nil {
		return errs.InternalError().AppendDetails("临时文件写入失败")
	}
	if err := tempWriter.Commit(); err != nil {
		return errs.InternalError().AppendDetails("临时文件写入完成失败")
	}
	defer func(name string) {
		if _, err := os.Stat(name); errors.Is(err, os.ErrNotExist) {
			return
		}
		if err := os.Remove(name); err != nil {
			slog.Warn("Failed to remove file", "error", err)
		}
	}(dst)

	jsonData, err := json.Marshal(&StoreFileReq{
		Slug:         request.Slug,
		FilePath:     rel,
		FileName:     request.FileName,
		ContentType:  request.ContentType,
		SHA512:       null.StringFrom(tempWriter.SHA512Sum()),
		IsPrivate:    request.IsPrivate,
		ShouldUpsert: request.ShouldUpsert,
		ShouldCopy:   request.ShouldCopy,
		UserID:       request.UserID,
		AppID:        request.AppID,
		BanComment:   request.BanComment,
	})
	if err != nil {
		return errs.InternalError().AppendDetails("请求序列化失败")
	}

	endpoint, err := url.JoinPath(cfg.C.FilestoreEndpoint, "/api/internal/upload/store")
	if err != nil {
		return errs.InternalError().AppendDetails("URL 路径拼接失败")
	}

	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return errs.InternalError().AppendDetails("文件上传请求创建失败")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", cfg.C.APIKey)

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return errs.InternalError().AppendDetails("文件上传请求发送失败")
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			slog.Warn("Failed to close response body", "error", err)
		}
	}(res.Body)

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return errs.InternalError().AppendDetails("读取响应失败")
	}
	if res.StatusCode != http.StatusOK {
		var errorInfo errs.ErrorInfo
		err := json.Unmarshal(body, &errorInfo)
		if err != nil {
			return errs.InternalError().AppendDetails("错误信息解析失败")
		}
		return &errs.Error{HTTPCode: res.StatusCode, Info: errorInfo}
	}

	return nil
}
