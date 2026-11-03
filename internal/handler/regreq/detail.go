package regreq

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/service/filestore"
	"fdfz-student-id/internal/service/perm"
	"fdfz-student-id/internal/service/user"
	"fdfz-student-id/internal/util/handling"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func getRegisterRequestHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)
	if !perm.HasPermission(claims, perm.PermRegisterRequestRead) {
		return errs.PermissionDeniedError().AppendDetails("权限不足", "鉴权失败").Seal()
	}

	id, e := uuid.Parse(c.Param("id"))
	if e != nil {
		return errs.BadRequestError().AppendDetails("无效的注册请求 ID")
	}

	request, err := user.GetRegisterRequestByID(c.Request.Context(), id)
	if err != nil {
		return err
	} else if request == nil {
		return errs.NotFoundError().AppendDetails("注册请求不存在")
	}

	c.JSON(http.StatusOK, gin.H{
		"id":               request.ID,
		"type":             request.Type,
		"student_num":      request.StudentNum,
		"real_name":        request.RealName,
		"school":           request.School,
		"username":         request.Username,
		"nickname":         request.Nickname,
		"created_at":       request.CreatedAt,
		"status":           request.Status,
		"created_user_id":  request.CreatedUserID,
		"reviewer_user_id": request.ReviewerUserID,
		"review_comment":   request.ReviewComment,
		"reviewed_at":      request.ReviewedAt,
	})
	return nil
}

func getRegisterRequestProofImageHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)
	if !perm.HasPermission(claims, perm.PermRegisterRequestRead) {
		return errs.PermissionDeniedError().AppendDetails("权限不足", "鉴权失败").Seal()
	}

	id, e := uuid.Parse(c.Param("id"))
	if e != nil {
		return errs.BadRequestError().AppendDetails("无效的注册请求 ID")
	}

	request, err := user.GetRegisterRequestByID(c.Request.Context(), id)
	if err != nil {
		return err
	} else if request == nil {
		return errs.NotFoundError().AppendDetails("注册请求不存在")
	}

	fileURL, err := filestore.BuildFileUrl("/student_id/proof_images/" + request.ID.String())
	if err != nil {
		return err
	}

	c.Redirect(http.StatusFound, fileURL)
	return nil
}
