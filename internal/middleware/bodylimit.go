package middleware

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/util/handling"

	"github.com/gin-gonic/gin"
)

const DefaultBodyLimit int64 = 1 << 20

// 不按 Content-Length 提前拒绝，以便需要更大上限的路由在读取前覆盖上限。
func DefaultLimitSize() gin.HandlerFunc {
	return func(c *gin.Context) {
		if _, ok := handling.GetBodyLimitReader(c); !ok {
			handling.InstallBodyLimitReader(c, DefaultBodyLimit)
		}
	}
}

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
