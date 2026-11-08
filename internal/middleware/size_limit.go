package middleware

import (
	"errors"
	"fdfz-student-id/internal/errs"
	"net/http"

	"github.com/gin-gonic/gin"
)

// LimitSize 把请求体大小限制为 maxBytes 字节，超限时返回 413 request_too_large。
// 注意：MaxBytesReader 只会在处理器读取请求体时报错，因此超限错误在 c.Next() 结束后
// 从 c.Errors 中识别；本中间件必须挂在读取请求体的处理器之前。
func LimitSize(maxBytes int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		c.Next()
		if c.Errors.Last() != nil {
			if _, ok := errors.AsType[*http.MaxBytesError](c.Errors.Last().Err); ok {
				errs.RequestTooLargeError().AppendDetails("请求体大小超出限制").Respond(c)
				return
			}
		}
	}
}
