package regreq

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/service/captcha"
	"fdfz-student-id/internal/service/user"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func registerRequestStatusHandler(c *gin.Context) *errs.Error {
	if err := captcha.VerifyPayloadStr(c.Request.Context(), c.Query("altcha_payload")); err != nil {
		return err
	}

	id, e := uuid.Parse(c.Query("id"))
	if e != nil {
		return errs.BadRequestError().AppendDetails("无效的注册请求 ID")
	}

	req, err := user.GetRegisterRequestByID(c.Request.Context(), id)
	if err != nil {
		return err
	}
	if req == nil {
		return errs.NotFoundError().AppendDetails("注册请求不存在")
	}

	c.JSON(http.StatusOK, gin.H{
		"status":         req.Status,
		"review_comment": req.ReviewComment,
		"reviewed_at":    req.ReviewedAt,
	})
	return nil
}
