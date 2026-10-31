package regreq

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/service/captcha"
	"fdfz-student-id/internal/service/user"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func registerRequestStatusHandler(c *gin.Context) {
	if err := captcha.VerifyPayloadStr(c.Query("altcha_payload")); err != nil {
		err.AppendDetails("注册请求状态查询失败").Respond(c)
		return
	}

	id, error := uuid.Parse(c.Query("id"))
	if error != nil {
		errs.BadRequestError().AppendDetails("无效的注册请求 ID", "注册请求状态查询失败").Respond(c)
		return
	}

	req, err := user.GetRegisterRequestByID(c.Request.Context(), id)
	if err != nil {
		err.AppendDetails("注册请求状态查询失败").Respond(c)
		return
	}
	if req == nil {
		errs.NotFoundError().AppendDetails("注册请求不存在", "注册请求状态查询失败").Respond(c)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":         req.Status,
		"review_comment": req.ReviewComment,
		"reviewed_at":    req.ReviewedAt,
	})
}
