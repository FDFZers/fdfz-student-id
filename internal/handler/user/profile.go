package user

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/service/user"
	"fdfz-student-id/internal/util/handling"
	"net/http"

	"github.com/gin-gonic/gin"
)

// getUserProfileByUsernameHandler 按用户名查询用户资料。
// 用户不存在时返回 404；已注销用户由 filterProfiles 决定返回最小化标识（非管理员）或正常字段（管理员）。
func getUserProfileByUsernameHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)
	targetUsername := c.Param("username")

	targetUser, err := user.GetUserByUsernameIncludingDeleted(c.Request.Context(), targetUsername)
	if err != nil {
		return err
	} else if targetUser == nil {
		return errs.NotFoundError().AppendDetails("用户不存在")
	}

	filtered, err := filterProfiles(c.Request.Context(), claims, targetUser)
	if err != nil {
		return err
	}

	c.JSON(http.StatusOK, filtered[0])
	return nil
}

// getUserProfileByIDHandler 按用户 ID 查询用户资料；未带 :id 路径参数时查询当前登录用户。
// 用户不存在时返回 404；已注销用户由 filterProfiles 决定返回最小化标识（非管理员）或正常字段（管理员）。
func getUserProfileByIDHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)
	targetID, err := handling.ParseUserID(c, claims.UserID, "id")
	if err != nil {
		return err
	}

	targetUser, err := user.GetUserByIDIncludingDeleted(c.Request.Context(), targetID)
	if err != nil {
		return err
	} else if targetUser == nil {
		return errs.NotFoundError().AppendDetails("用户不存在")
	}

	filtered, err := filterProfiles(c.Request.Context(), claims, targetUser)
	if err != nil {
		return err
	}

	c.JSON(http.StatusOK, filtered[0])
	return nil
}
