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

func reviewRegisterHandler(c *gin.Context) {
	var req reviewRegisterReq
	if err := c.ShouldBindJSON(&req); err != nil {
		errs.BadRequestError().AppendDetails("请求解析失败", "注册请求审核失败").Respond(c)
		return
	}

	if req.ID == uuid.Nil {
		errs.BadRequestError().AppendDetails("无效的注册请求 ID", "注册请求审核失败").Respond(c)
		return
	}

	claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)
	if !perm.Contains(claims.Permissions, "student_id.register_requests.review") {
		errs.PermissionDeniedError().AppendDetails("权限不足", "鉴权失败").Respond(c)
		return
	}

	if err := user.ReviewRegisterRequest(c.Request.Context(), req.ID, req.Status, req.Comment, claims.UserID); err != nil {
		err.Respond(c)
		return
	}

	c.JSON(http.StatusOK, gin.H{})
}
