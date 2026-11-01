package regreq

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/service/perm"
	"fdfz-student-id/internal/service/user"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type reviewRegisterReq struct {
	ID      uuid.UUID                   `json:"id"`
	Status  model.RegisterRequestStatus `json:"status"`
	Comment string                      `json:"comment"`
}

func reviewRegisterHandler(c *gin.Context) *errs.Error {
	var req reviewRegisterReq
	if err := c.ShouldBindJSON(&req); err != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}

	if req.ID == uuid.Nil {
		return errs.BadRequestError().AppendDetails("无效的注册请求 ID")
	}

	if !req.Status.IsValid() || req.Status == model.RegisterRequestStatusPending {
		return errs.BadRequestError().AppendDetails("无效的审核状态")
	}

	claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)
	if !perm.Contains(claims.Permissions, "student_id.register_requests.review") {
		return errs.PermissionDeniedError().AppendDetails("权限不足", "鉴权失败").Seal()
	}

	if err := user.ReviewRegisterRequest(c.Request.Context(), req.ID, req.Status, req.Comment, claims.UserID); err != nil {
		// 服务层错误已自带 "注册请求审核失败"，直接返回以保持响应不变。
		return err.Seal()
	}

	c.JSON(http.StatusOK, gin.H{})
	return nil
}
