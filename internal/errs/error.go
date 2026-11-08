// Package errs 定义统一的 API 错误对象：错误 id + HTTP 状态码 + 可选的中文 details。
//
// 处理器返回 *Error，由 handling.Wrap 统一写响应；错误对象在返回途中可继续追加 details
// （具体原因在前），端点级失败文案由路由层的 Wrap 统一追加在最后。
package errs

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ErrorInfo 是错误响应体：error 为稳定的英文错误 id，details 为给用户看的中文说明。
type ErrorInfo struct {
	Error   string   `json:"error"`
	Details []string `json:"details,omitempty"`
}

// Error 是对外返回的错误对象。sealed 为 true 时，handling.Wrap 不会再自动追加端点级文案。
type Error struct {
	HTTPCode int
	Info     ErrorInfo
	sealed   bool
}

// CreateError 按 HTTP 状态码和错误 id 创建错误对象。
func CreateError(httpCode int, id string) *Error {
	return &Error{
		HTTPCode: httpCode,
		Info: ErrorInfo{
			Error: id,
		},
	}
}

// AppendDetails 在 details 末尾追加说明；返回自身以支持链式调用。
// 注意：只追加具体原因或子步骤失败，不要追加与路由 Wrap 文案重复的端点级失败文案。
func (err *Error) AppendDetails(detail ...string) *Error {
	err.Info.Details = append(err.Info.Details, detail...)
	return err
}

// Seal 标记错误已“封口”：Wrap 不再自动追加端点级失败文案。
// 用于 details 已经完整、不希望再被追加通用文案的场景。
func (err *Error) Seal() *Error {
	err.sealed = true
	return err
}

// IsSealed 返回错误是否已被 Seal。
func (err *Error) IsSealed() bool {
	return err.sealed
}

// Respond 把错误写为响应，不中断后续中间件。
func (err *Error) Respond(c *gin.Context) {
	c.JSON(err.HTTPCode, err.Info)
}

// Abort 把错误写为响应并中断请求处理，用于中间件。
func (err *Error) Abort(c *gin.Context) {
	c.AbortWithStatusJSON(err.HTTPCode, err.Info)
}

// InternalError 返回 500 internal_error，表示服务器内部错误。
func InternalError() *Error {
	return CreateError(http.StatusInternalServerError, "internal_error")
}

// BadRequestError 返回 400 bad_request，表示请求参数或格式有误。
func BadRequestError() *Error {
	return CreateError(http.StatusBadRequest, "bad_request")
}

// IllegalStateError 返回 403 illegal_state，表示当前状态不允许该操作。
func IllegalStateError() *Error {
	return CreateError(http.StatusForbidden, "illegal_state")
}

// RequestTooLargeError 返回 413 request_too_large，表示请求体超出大小限制。
func RequestTooLargeError() *Error {
	return CreateError(http.StatusRequestEntityTooLarge, "request_too_large")
}

// RateLimitExceededError 返回 429 rate_limit_exceeded，表示触发频率限制。
func RateLimitExceededError() *Error {
	return CreateError(http.StatusTooManyRequests, "rate_limit_exceeded")
}

// ForbiddenError 返回 403 forbidden，表示操作被拒绝（如用户名密码错误）。
func ForbiddenError() *Error {
	return CreateError(http.StatusForbidden, "forbidden")
}

// InvalidTokenError 返回 401 invalid_token，表示令牌缺失、格式错误或无效。
func InvalidTokenError() *Error {
	return CreateError(http.StatusUnauthorized, "invalid_token")
}

// TokenExpiredError 返回 401 token_expired，表示令牌已过期。
func TokenExpiredError() *Error {
	return CreateError(http.StatusUnauthorized, "token_expired")
}

// PermissionDeniedError 返回 403 permission_denied，表示已登录但缺少所需权限。
func PermissionDeniedError() *Error {
	return CreateError(http.StatusForbidden, "permission_denied")
}

// UnsupportedMediaTypeError 返回 415 unsupported_media_type，表示上传的文件类型不受支持。
func UnsupportedMediaTypeError() *Error {
	return CreateError(http.StatusUnsupportedMediaType, "unsupported_media_type")
}

// NotFoundError 返回 404 not_found，表示请求的资源不存在。
func NotFoundError() *Error {
	return CreateError(http.StatusNotFound, "not_found")
}

// ConflictError 返回 409 conflict，表示唯一约束或状态冲突。
func ConflictError() *Error {
	return CreateError(http.StatusConflict, "conflict")
}

// AltchaError 返回 403 altcha_error，表示人机验证（Altcha）未通过。
func AltchaError() *Error {
	return CreateError(http.StatusForbidden, "altcha_error")
}

// CreateAndLogInternalError 记录一条 error 级日志并返回 500 internal_error。
// 调用方可继续 AppendDetails 追加对用户更友好的原因说明。
func CreateAndLogInternalError[T any](err T, log string, args ...any) *Error {
	slog.Error(log, append([]any{"error", err}, args...)...)
	return InternalError()
}

// CreatePGError 把 PostgreSQL 错误映射为 API 错误，并保留调用方提供的具体原因。
//
//   - 查询无结果（pgx.ErrNoRows）：404 not_found，details 为「“item”不存在」；
//   - 唯一约束等 SQLSTATE 23xxx 冲突：409 conflict，details 带约束名；
//   - 其它数据库错误：500 internal_error，details 为「PostgreSQL 内部错误」。
//
// 注意：这里返回的 details 只描述具体原因，调用方不要再追加与路由 Wrap 重复的端点级失败文案。
func CreatePGError(err error, item, log string) *Error {
	if errors.Is(err, pgx.ErrNoRows) {
		return NotFoundError().AppendDetails(fmt.Sprintf("“%s”不存在", item))
	}

	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || !strings.HasPrefix(pgErr.Code, "23") {
		return CreateAndLogInternalError(err, log).AppendDetails("PostgreSQL 内部错误")
	}

	return ConflictError().AppendDetails(fmt.Sprintf("“%s”冲突", pgErr.ConstraintName), "PostgreSQL 错误")
}
