package middleware

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/util/handling"

	"github.com/gin-gonic/gin"
)

// DefaultBodyLimit 是全局默认请求体上限（1 MiB）。
const DefaultBodyLimit int64 = 1 << 20

// DefaultLimitSize 安装全局默认请求体上限（1 MiB）。
// 注意：这里不按 Content-Length 提前拒绝，以便需要更大上限的路由通过 LimitSize(max) 在读取前
// “重新设置”上限；普通路由读取超过 1 MiB 时由读取器报错，handling.Wrap 统一返回 413。
func DefaultLimitSize() gin.HandlerFunc {
	return func(c *gin.Context) {
		if _, ok := handling.GetBodyLimitReader(c); !ok {
			handling.InstallBodyLimitReader(c, DefaultBodyLimit)
		}
	}
}

// LimitSize 把请求体大小限制为 maxBytes 字节，超限时返回 413 request_too_large。
// 若全局默认上限已安装且尚未读取请求体，本中间件会重新设置上限（用于注册/头像等 5 MiB 路由）；
// 已知 Content-Length 超限时在进入处理器前直接拒绝。
func LimitSize(maxBytes int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if r, ok := handling.GetBodyLimitReader(c); ok {
			r.SetLimit(maxBytes)
		} else {
			handling.InstallBodyLimitReader(c, maxBytes)
		}

		if c.Request.ContentLength > maxBytes {
			errs.RequestTooLargeError().AppendDetails("请求体大小超出限制").Abort(c)
			return
		}
		c.Next()
	}
}
