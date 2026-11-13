package regreq

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/service/perm"
	"fdfz-student-id/internal/service/user"
	"fdfz-student-id/internal/util/handling"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// reviewRegisterReq 注册申请审核请求；status 只能是 approved 或 rejected。
type reviewRegisterReq struct {
	ID      uuid.UUID                   `json:"id"`
	Status  model.RegisterRequestStatus `json:"status"`
	Comment string                      `json:"comment"`
}

// reviewRegisterHandler 审核注册申请：校验 ID/状态/审核意见与 register_requests.review 权限后交给服务层处理。
// 审核通过会在同一事务内创建用户并回写 created_user_id，失败整体回滚；这里不 Seal 以便 Wrap 追加端点级文案。
func reviewRegisterHandler(c *gin.Context) *errs.Error {
	var req reviewRegisterReq
	if e := c.ShouldBindJSON(&req); e != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}

	if err := handling.ValidateUUID(req.ID, "注册请求 ID"); err != nil {
		return err
	}

	if err := handling.ValidateRegisterReviewStatus(req.Status); err != nil {
		return err
	}
	if err := handling.ValidateRegisterReviewComment(req.Comment); err != nil {
		return err
	}

	claims := handling.MustGetClaims(c)
	if !perm.HasPermission(claims, perm.PermRegisterRequestReview) {
		return errs.PermissionDeniedError().AppendDetails("权限不足").Seal()
	}

	if err := user.ReviewRegisterRequest(c.Request.Context(), req.ID, req.Status, req.Comment, claims.UserID); err != nil {
		return err
	}

	slog.Info("Register request reviewed", "register_id", req.ID, "status", req.Status, "reviewer_id", claims.UserID)

	c.JSON(http.StatusOK, gin.H{})
	return nil
}
