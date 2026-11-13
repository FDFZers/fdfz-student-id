package regreq

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/service/captcha"
	"fdfz-student-id/internal/service/user"
	"fdfz-student-id/internal/util/handling"
	"net/http"

	"github.com/gin-gonic/gin"
)

// registerRequestStatusHandler 查询注册申请的审核状态，无需登录。
// 凭申请 ID + Altcha 人机验证即可查询，只返回状态、审核意见与审核时间，不泄露表单内容。
func registerRequestStatusHandler(c *gin.Context) *errs.Error {
	if err := captcha.VerifyPayloadStr(c.Request.Context(), c.Query("altcha_payload")); err != nil {
		return err
	}

	id, err := handling.ParseUUID(c.Query("id"), "注册请求 ID")
	if err != nil {
		return err
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
