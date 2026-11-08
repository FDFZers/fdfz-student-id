// Package filestore 封装文件存储服务：HMAC 令牌签发、文件上传/删除、文件地址拼接。
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
	tokenSeparator = "." // 分隔令牌中的 Unix 时间戳与 HMAC 签名

	uploadTimeout = 30 * time.Second // 调用 filestore HTTP 接口的超时时间
)

// httpClient 是调用 filestore 的共享 HTTP 客户端。
var httpClient = &http.Client{Timeout: uploadTimeout}

// StoreFileReq 是上传到 filestore 的请求体。
// 注意：FilePath 是相对 SHARED_DIR 的路径，SHA512 由本地临时文件计算，供 filestore 校验。
type StoreFileReq struct {
	Slug         string      `json:"slug"`          // 文件 slug，必须以 / 开头，如 /student_id/avatars/1
	FilePath     string      `json:"file_path"`     // 相对 SHARED_DIR 的文件路径，由 storage.UploadTempPath 生成
	FileName     string      `json:"file_name"`     // 展示用文件名（含扩展名）
	Description  string      `json:"description"`   // 文件描述
	ContentType  null.String `json:"content_type"`  // 客户端声明的 MIME 类型，可为空
	SHA512       null.String `json:"sha512"`        // 文件内容的 SHA-512，供 filestore 校验完整性
	ShouldUpsert bool        `json:"should_upsert"` // slug 已存在时是否覆盖
	ShouldCopy   bool        `json:"should_copy"`   // 透传 filestore 的 should_copy 选项，语义由下游定义
	UserID       null.Int64  `json:"user_id"`       // 关联用户 ID，可为空
	AppID        null.Int64  `json:"app_id"`        // 关联应用 ID，可为空
}

// ---------------------------------------------------------------------------
// 令牌
// ---------------------------------------------------------------------------

// CreateDownloadToken 为指定 slug 签发下载令牌。
func CreateDownloadToken(slug string) (string, *errs.Error) {
	return CreateTokenAt(slug, model.FileTokenTypeDownload, time.Now())
}

// CreateUploadToken 为指定 slug 签发上传令牌（删除接口复用该令牌类型）。
func CreateUploadToken(slug string) (string, *errs.Error) {
	return CreateTokenAt(slug, model.FileTokenTypeUpload, time.Now())
}

// CreateTokenAt 按「Unix 时间戳.签名」格式签发指定类型的文件令牌。
// 注意：tokenType 只能是 upload 或 download，其他取值返回内部错误。
func CreateTokenAt(slug string, tokenType model.FileTokenType, t time.Time) (string, *errs.Error) {
	if tokenType != model.FileTokenTypeDownload && tokenType != model.FileTokenTypeUpload {
		return "", errs.CreateAndLogInternalError(errors.New("invalid token type"),
			"Invalid filestore token type",
			"token_type", tokenType,
		).AppendDetails("文件令牌类型不受支持")
	}
	timestamp := t.Unix()
	return strconv.FormatInt(timestamp, 10) + tokenSeparator +
		signSlugToken(cfg.C.FilestoreHMACSecret, slug, tokenType, timestamp), nil
}

// signSlugToken 用 FILESTORE_HMAC_SECRET 对 slug、令牌类型与时间戳做 HMAC-SHA256 签名。
func signSlugToken(secret, slug string, tokenType model.FileTokenType, timestamp int64) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(slug))
	mac.Write([]byte("\n"))
	mac.Write([]byte(tokenType))
	mac.Write([]byte("\n"))
	mac.Write(strconv.AppendInt(nil, timestamp, 10))
	return hex.EncodeToString(mac.Sum(nil))
}

// BuildFileUrl 拼接文件下载地址（携带下载令牌）。
func BuildFileUrl(slug string) (string, *errs.Error) {
	return buildUrl(slug, "file")
}

// BuildInfoUrl 拼接文件信息查询地址（携带下载令牌）。
// 注意：当前仓库内暂无调用方，保留给后续查询文件元数据的场景。
func BuildInfoUrl(slug string) (string, *errs.Error) {
	return buildUrl(slug, "info")
}

// buildUrl 拼接「FILESTORE_PUBLIC_ENDPOINT/internal/v1/{reqType}/{slug}?token=...」。
// reqType 为 file（下载）或 info（元数据）；slug 必须以 / 开头。
func buildUrl(slug, reqType string) (string, *errs.Error) {
	if !strings.HasPrefix(slug, "/") {
		return "", errs.BadRequestError().AppendDetails("Slug 格式错误")
	}

	token, err := CreateDownloadToken(slug)
	if err != nil {
		return "", err
	}

	endpoint, e := url.JoinPath(cfg.C.FilestorePublicEndpoint, "/internal/v1/"+reqType, slug)
	if e != nil {
		return "", errs.CreateAndLogInternalError(e, "Failed to build file URL").AppendDetails("URL 路径拼接失败")
	}

	query := url.Values{"token": {token}}
	return endpoint + "?" + query.Encode(), nil
}

// ---------------------------------------------------------------------------
// 上传
// ---------------------------------------------------------------------------

// UploadFile 把 multipart 文件先写入 SHARED_DIR 下的临时文件，再调用 filestore 内部上传接口。
// 会返回 filestore 的错误对象（保留其 HTTP 状态码与 details）；请求结束后删除本地临时文件。
// 注意：文件大小由调用方的限流中间件控制，本函数不做大小校验。
func UploadFile(fileHeader *multipart.FileHeader, request *StoreFileReq) *errs.Error {
	if request == nil {
		return errs.CreateAndLogInternalError(errors.New("nil upload request"), "File upload request is nil").AppendDetails("未提供文件上传请求", "文件上传失败")
	}
	if !strings.HasPrefix(request.Slug, "/") {
		return errs.BadRequestError().AppendDetails("Slug 格式错误", "文件上传失败")
	}
	if fileHeader == nil {
		return errs.CreateAndLogInternalError(errors.New("nil file header"), "File header is nil").AppendDetails("未提供文件", "文件上传失败")
	}

	// 签发上传令牌
	token, err := CreateUploadToken(request.Slug)
	if err != nil {
		return err.AppendDetails("文件上传失败")
	}

	// 生成本地临时路径并创建临时文件
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

	// 把请求体文件写入临时文件，同时计算 SHA-512
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

	if _, e := tempWriter.WriteFrom(file); e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to write temp file").AppendDetails("临时文件写入失败")
	}
	if e := tempWriter.Commit(); e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to commit temp file").AppendDetails("临时文件保存失败")
	}

	// 组装上传请求体
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

	// 调用 filestore 内部上传接口
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

	// 解析响应：非 200 时优先透传 filestore 的错误对象
	body, e := io.ReadAll(res.Body)
	if e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to read response body").AppendDetails("读取响应失败")
	}
	if res.StatusCode != http.StatusOK {
		var errorInfo errs.ErrorInfo
		if e := json.Unmarshal(body, &errorInfo); e != nil || errorInfo.Error == "" {
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

// DeleteFile 调用 filestore 内部接口删除指定 slug 的文件。
// 404 等下游错误会以 filestore 的错误对象透传，调用方可根据 HTTP 状态码区分「文件不存在」。
func DeleteFile(slug string) *errs.Error {
	if !strings.HasPrefix(slug, "/") {
		return errs.BadRequestError().AppendDetails("Slug 格式错误", "文件删除失败")
	}

	// 签发上传令牌（删除接口复用上传令牌）
	token, err := CreateUploadToken(slug)
	if err != nil {
		return err.AppendDetails("文件删除失败")
	}

	// 调用 filestore 内部删除接口
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

	// 解析响应：非 200 时优先透传 filestore 的错误对象
	body, e := io.ReadAll(res.Body)
	if e != nil {
		return errs.CreateAndLogInternalError(e, "Failed to read response body").AppendDetails("读取响应失败")
	}
	if res.StatusCode != http.StatusOK {
		var errorInfo errs.ErrorInfo
		if e := json.Unmarshal(body, &errorInfo); e != nil || errorInfo.Error == "" {
			slog.Warn("Failed to parse filestore error response",
				"status", res.StatusCode, "body", string(body))
			return errs.CreateError(res.StatusCode, "filestore_error").AppendDetails("文件删除失败")
		}
		return &errs.Error{HTTPCode: res.StatusCode, Info: errorInfo}
	}

	return nil
}
