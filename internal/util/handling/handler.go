package handling

import (
	"fdfz-student-id/internal/errs"

	"github.com/gin-gonic/gin"
)

// Handler 是返回 *errs.Error 的 HTTP 处理器函数，由 Wrap 包装后注册到 gin 路由。
type Handler func(c *gin.Context) *errs.Error

// Wrap 把 Handler 包装成 gin.HandlerFunc，统一处理错误响应：
//   - 处理器返回 nil：说明已自行写入响应，直接结束；
//   - 错误已 Seal：只按错误内容响应，不再追加文案；
//   - 其他错误：在 details 末尾追加端点级失败文案 failMsg 后响应。
//
// failMsg 形如「用户组创建失败」，代表整个端点的操作上下文，因此处理器内部不要再
// 手动追加同义文案，否则响应中的 details 会重复。
func Wrap(failMsg string, h Handler) gin.HandlerFunc {
	return func(c *gin.Context) {
		err := h(c)
		if err == nil {
			return
		}
		if BodyLimitExceeded(c) {
			errs.RequestTooLargeError().AppendDetails("请求体大小超出限制").Respond(c)
			return
		}
		if err.IsSealed() {
			err.Respond(c)
			return
		}
		err.AppendDetails(failMsg).Respond(c)
	}
}
