package handling

import (
	"fdfz-student-id/internal/errs"

	"github.com/gin-gonic/gin"
)

type Handler func(c *gin.Context) *errs.Error

func Wrap(failMsg string, h Handler) gin.HandlerFunc {
	return func(c *gin.Context) {
		err := h(c)
		if err == nil {
			return
		}
		if err.IsSealed() {
			err.Respond(c)
			return
		}
		err.AppendDetails(failMsg).Respond(c)
	}
}
