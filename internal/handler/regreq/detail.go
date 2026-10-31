package regreq

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/service/filestore"
	"fdfz-student-id/internal/service/perm"
	"fdfz-student-id/internal/service/user"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func getRegisterRequestHandler(c *gin.Context) {
	claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)
	if !perm.Contains(claims.Permissions, "student_id.register_requests.read") {
		errs.PermissionDeniedError().AppendDetails("权限不足", "鉴权失败").Respond(c)
		return
	}

	id, error := uuid.Parse(c.Param("id"))
	if error != nil {
		errs.BadRequestError().AppendDetails("无效的注册请求 ID", "注册申请获取失败").Respond(c)
		return
	}

	request, err := user.GetRegisterRequestByID(c.Request.Context(), id)
	if err != nil {
		err.AppendDetails("注册申请获取失败").Respond(c)
		return
	} else if request == nil {
		errs.NotFoundError().AppendDetails("注册请求不存在", "注册申请获取失败").Respond(c)
		return
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
}

func getRegisterRequestProofImageHandler(c *gin.Context) {
	claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)
	if !perm.ContainsAny(claims.Permissions, "student_id.register_requests.read") {
		errs.PermissionDeniedError().AppendDetails("权限不足", "鉴权失败").Respond(c)
		return
	}

	id, error := uuid.Parse(c.Param("id"))
	if error != nil {
		errs.BadRequestError().AppendDetails("无效的注册请求 ID", "佐证图片获取失败").Respond(c)
		return
	}

	request, err := user.GetRegisterRequestByID(c.Request.Context(), id)
	if err != nil {
		err.AppendDetails("佐证图片获取失败").Respond(c)
		return
	} else if request == nil {
		errs.NotFoundError().AppendDetails("注册请求不存在", "佐证图片获取失败").Respond(c)
		return
	}

	fileURL, err := filestore.BuildFileUrl("/student_id/proof_images/" + request.ID.String())
	if err != nil {
		err.AppendDetails("佐证图片获取失败").Respond(c)
		return
	}

	c.Redirect(http.StatusFound, fileURL)
}
