package regreq

import (
	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	permsvc "fdfz-student-id/internal/service/perm"
	usersvc "fdfz-student-id/internal/service/user"
	"fdfz-student-id/internal/util/handling"
	"log/slog"

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
	if err := handling.BindJSON(c, &req); err != nil {
		return err
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
	if !permsvc.HasPermission(claims, permsvc.PermRegisterRequestReview) {
		return errs.PermissionDeniedError().AppendDetails("权限不足").Seal()
	}

	if err := usersvc.ReviewRegisterRequest(c.Request.Context(), db.R, req.ID, req.Status, req.Comment, claims.UserID); err != nil {
		return err
	}

	slog.Info("Register request reviewed", "register_id", req.ID, "status", req.Status, "reviewer_id", claims.UserID)

	handling.RespondOK(c)
	return nil
}
