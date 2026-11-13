package regreq

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/service/filestore"
	"fdfz-student-id/internal/service/perm"
	"fdfz-student-id/internal/service/user"
	"fdfz-student-id/internal/util/handling"
	"net/http"

	"github.com/gin-gonic/gin"
)

// getRegisterRequestHandler 查询单条注册申请详情，需要 register_requests.read 权限。
// 注意：响应包含表单中的身份信息与审核信息，但不返回密码哈希。
func getRegisterRequestHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)
	if !perm.HasPermission(claims, perm.PermRegisterRequestRead) {
		return errs.PermissionDeniedError().AppendDetails("权限不足").Seal()
	}

	id, err := handling.ParseUUID(c.Param("id"), "注册请求 ID")
	if err != nil {
		return err
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

// getRegisterRequestProofImageHandler 获取注册申请的佐证图片：校验权限后 302 重定向到 filestore 地址。
// 注意：只校验注册申请存在，不校验图片是否已上传成功，文件缺失时由 filestore 返回 404。
func getRegisterRequestProofImageHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)
	if !perm.HasPermission(claims, perm.PermRegisterRequestRead) {
		return errs.PermissionDeniedError().AppendDetails("权限不足").Seal()
	}

	id, err := handling.ParseUUID(c.Param("id"), "注册请求 ID")
	if err != nil {
		return err
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
