package filestore

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fdfz-student-id/internal/cfg"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	fileutils "fdfz-student-id/internal/util/file"
	"fdfz-student-id/internal/util/storage"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/guregu/null/v6"
)

const (
	tokenSeparator = "."

	uploadTimeout = 30 * time.Second
)

var httpClient = &http.Client{Timeout: uploadTimeout}

type StoreFileReq struct {
	Slug         string      `json:"slug"`
	FilePath     string      `json:"file_path"`
	FileName     string      `json:"file_name"`
	Description  string      `json:"description"`
	ContentType  null.String `json:"content_type"`
	SHA512       null.String `json:"sha512"`
	ShouldUpsert bool        `json:"should_upsert"`
	ShouldCopy   bool        `json:"should_copy"`
	UserID       null.Int64  `json:"user_id"`
	AppID        null.Int64  `json:"app_id"`
}

// ---------------------------------------------------------------------------
// 令牌
// ---------------------------------------------------------------------------

func CreateDownloadToken(slug string) (string, *errs.Error) {
	return CreateTokenAt(slug, model.FileTokenTypeDownload, time.Now())
}

func CreateUploadToken(slug string) (string, *errs.Error) {
	return CreateTokenAt(slug, model.FileTokenTypeUpload, time.Now())
}

func CreateTokenAt(slug string, tokenType model.FileTokenType, t time.Time) (string, *errs.Error) {
	if tokenType != model.FileTokenTypeDownload && tokenType != model.FileTokenTypeUpload {
		return "", errs.CreateAndLogInternalError(errors.New("invalid token type"),
			"Invalid filestore token type",
			"token_type", tokenType,
		).AppendDetails("无效的文件令牌类型")
	}
	timestamp := t.Unix()
	return strconv.FormatInt(timestamp, 10) + tokenSeparator +
		signSlugToken(cfg.C.FilestoreHMACSecret, slug, tokenType, timestamp), nil
}

func signSlugToken(secret, slug string, tokenType model.FileTokenType, timestamp int64) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(slug))
	mac.Write([]byte("\n"))
	mac.Write([]byte(tokenType))
	mac.Write([]byte("\n"))
	mac.Write(strconv.AppendInt(nil, timestamp, 10))
	return hex.EncodeToString(mac.Sum(nil))
}

func BuildFileUrl(slug string) (string, *errs.Error) {
	return buildUrl(slug, "file")
}

func BuildInfoUrl(slug string) (string, *errs.Error) {
	return buildUrl(slug, "info")
}

func buildUrl(slug, reqType string) (string, *errs.Error) {
	if !strings.HasPrefix(slug, "/") {
		return "", errs.BadRequestError().AppendDetails("无效的 Slug", "文件地址获取失败")
	}

	token, err := CreateDownloadToken(slug)
	if err != nil {
		return "", err.AppendDetails("文件地址获取失败")
	}

	endpoint, e := url.JoinPath(cfg.C.FilestorePublicEndpoint, "/internal/v1/"+reqType, slug)
	if e != nil {
		return "", errs.CreateAndLogInternalError(e, "Failed to build file URL").AppendDetails("URL 路径拼接失败", "文件地址获取失败")
	}

	query := url.Values{"token": {token}}
	return endpoint + "?" + query.Encode(), nil
}

// ---------------------------------------------------------------------------
// 上传
// ---------------------------------------------------------------------------

func UploadFile(fileHeader *multipart.FileHeader, request *StoreFileReq) *errs.Error {
	if request == nil {
		return errs.CreateAndLogInternalError(errors.New("nil upload request"), "File upload request is nil").AppendDetails("未提供文件上传请求", "文件上传失败")
	}
	if !strings.HasPrefix(request.Slug, "/") {
		return errs.BadRequestError().AppendDetails("无效的 Slug", "文件上传失败")
	}
	if fileHeader == nil {
		return errs.CreateAndLogInternalError(errors.New("nil file header"), "File header is nil").AppendDetails("未提供文件", "文件上传失败")
	}

	token, err := CreateUploadToken(request.Slug)
	if err != nil {
		return err.AppendDetails("文件上传失败")
	}

	rel, dst, e := storage.UploadTempPath()
	if e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to get temp file path").AppendDetails("临时文件路径获取失败")
	}
	tempWriter, e := fileutils.NewTempWriter(dst, nil)
	if e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to create temp file").AppendDetails("临时文件创建失败")
	}
	defer func() {
		tempWriter.Abort()
		if _, err := os.Stat(dst); errors.Is(err, os.ErrNotExist) {
			return
		}
		if err := os.Remove(dst); err != nil {
			slog.Warn("Failed to remove file", "error", err)
		}
	}()

	file, e := fileHeader.Open()
	if e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to open request file").AppendDetails("请求体文件打开失败")
	}
	defer func(file multipart.File) {
		err := file.Close()
		if err != nil {
			slog.Warn("Failed to close file", "error", err)
		}
	}(file)

	if _, err := tempWriter.WriteFrom(file); err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to write temp file").AppendDetails("临时文件写入失败")
	}
	if err := tempWriter.Commit(); err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to commit temp file").AppendDetails("临时文件写入完成失败")
	}

	jsonData, e := json.Marshal(&StoreFileReq{
		Slug:         request.Slug,
		FilePath:     rel,
		FileName:     request.FileName,
		Description:  request.Description,
		ContentType:  request.ContentType,
		SHA512:       null.StringFrom(tempWriter.SHA512Sum()),
		ShouldUpsert: request.ShouldUpsert,
		ShouldCopy:   request.ShouldCopy,
		UserID:       request.UserID,
		AppID:        request.AppID,
	})
	if e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to marshal upload request").AppendDetails("请求序列化失败")
	}

	endpoint, e := url.JoinPath(cfg.C.FilestoreInternalEndpoint, "/api/internal/upload/store")
	if e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to build upload URL").AppendDetails("URL 路径拼接失败")
	}

	req, e := http.NewRequest(http.MethodPost, endpoint, bytes.NewBuffer(jsonData))
	if e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to create upload request").AppendDetails("文件上传请求创建失败")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	res, e := httpClient.Do(req)
	if e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to send upload request").AppendDetails("文件上传请求发送失败")
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			slog.Warn("Failed to close response body", "error", err)
		}
	}(res.Body)

	body, e := io.ReadAll(res.Body)
	if e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to read response body").AppendDetails("读取响应失败")
	}
	if res.StatusCode != http.StatusOK {
		var errorInfo errs.ErrorInfo
		if err := json.Unmarshal(body, &errorInfo); err != nil || errorInfo.Error == "" {
			slog.Warn("Failed to parse filestore error response",
				"status", res.StatusCode, "body", string(body))
			return errs.CreateError(res.StatusCode, "filestore_error").AppendDetails("文件上传失败")
		}
		return &errs.Error{HTTPCode: res.StatusCode, Info: errorInfo}
	}

	return nil
}

// ---------------------------------------------------------------------------
// 删除
// ---------------------------------------------------------------------------

func DeleteFile(slug string) *errs.Error {
	if !strings.HasPrefix(slug, "/") {
		return errs.BadRequestError().AppendDetails("无效的 Slug", "文件删除失败")
	}

	token, err := CreateUploadToken(slug)
	if err != nil {
		return err.AppendDetails("文件删除失败")
	}

	endpoint, e := url.JoinPath(cfg.C.FilestoreInternalEndpoint, "/api/internal/file", slug)
	if e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to build delete URL").AppendDetails("URL 路径拼接失败", "文件删除失败")
	}

	req, e := http.NewRequest(http.MethodDelete, endpoint, nil)
	if e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to create delete request").AppendDetails("文件删除请求创建失败")
	}
	req.Header.Set("Authorization", "Bearer "+token)

	res, e := httpClient.Do(req)
	if e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to send delete request").AppendDetails("文件删除请求发送失败")
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			slog.Warn("Failed to close response body", "error", err)
		}
	}(res.Body)

	body, e := io.ReadAll(res.Body)
	if e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to read response body").AppendDetails("读取响应失败")
	}
	if res.StatusCode != http.StatusOK {
		var errorInfo errs.ErrorInfo
		if err := json.Unmarshal(body, &errorInfo); err != nil || errorInfo.Error == "" {
			slog.Warn("Failed to parse filestore error response",
				"status", res.StatusCode, "body", string(body))
			return errs.CreateError(res.StatusCode, "filestore_error").AppendDetails("文件删除失败")
		}
		return &errs.Error{HTTPCode: res.StatusCode, Info: errorInfo}
	}

	return nil
}
