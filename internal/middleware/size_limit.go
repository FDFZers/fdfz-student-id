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
			var maxBytesErr *http.MaxBytesError
			if errors.As(c.Errors.Last().Err, &maxBytesErr) {
				errs.RequestTooLargeError().AppendDetails("请求体大小超出限制").Respond(c)
				return
			}
		}
	}
}
