package regreq

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/service/user"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// registerRequestStatusHandler 供未登录的注册申请者凭注册申请 ID 查询审核状态。
func registerRequestStatusHandler(c *gin.Context) {
	id, err := uuid.Parse(c.Query("id"))
	if err != nil {
		errs.BadRequestError().AppendDetails("无效的注册请求 ID", "注册请求状态查询失败").Respond(c)
		return
	}

	req, getErr := user.GetRegisterRequestByID(c.Request.Context(), id)
	if getErr != nil {
		getErr.AppendDetails("注册请求状态查询失败").Respond(c)
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
