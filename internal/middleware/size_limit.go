package middleware

import (
	"errors"
	"fdfz-student-id/internal/errs"
	"net/http"

	"github.com/gin-gonic/gin"
)

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
