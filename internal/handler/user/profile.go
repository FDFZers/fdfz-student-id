package user

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/service/user"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

func getUserProfileByUsernameHandler(c *gin.Context) {
	claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)
	targetUsername := c.Param("username")

	targetUser, err := user.GetUserByUsername(c.Request.Context(), targetUsername)
	if err != nil {
		err.AppendDetails("获取用户信息失败").Respond(c)
		return
	} else if targetUser == nil {
		errs.NotFoundError().AppendDetails("用户不存在", "获取用户信息失败").Respond(c)
		return
	}
	c.JSON(http.StatusOK, filterProfiles(claims, targetUser)[0])
}

func getUserProfileByIDHandler(c *gin.Context) {
	claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)
	targetIDStr := c.Param("id")
	targetID, err := strconv.ParseInt(targetIDStr, 10, 64)
	if err != nil {
		errs.BadRequestError().AppendDetails("无效的用户ID", "获取用户信息失败").Respond(c)
		return
	}

	targetUser, uErr := user.GetUserByID(c.Request.Context(), targetID)
	if uErr != nil {
		uErr.AppendDetails("获取用户信息失败").Respond(c)
		return
	} else if targetUser == nil {
		errs.NotFoundError().AppendDetails("用户不存在", "获取用户信息失败").Respond(c)
		return
	}
	c.JSON(http.StatusOK, filterProfiles(claims, targetUser)[0])
}
