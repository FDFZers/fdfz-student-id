package user

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/service/user"
	"net/http"

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
	targetID, err := ResolveTargetID(c, claims.UserID)
	if err != nil {
		err.AppendDetails("获取用户信息失败").Respond(c)
		return
	}

	targetUser, err := user.GetUserByID(c.Request.Context(), targetID)
	if err != nil {
		err.AppendDetails("获取用户信息失败").Respond(c)
		return
	} else if targetUser == nil {
		errs.NotFoundError().AppendDetails("用户不存在", "获取用户信息失败").Respond(c)
		return
	}
	c.JSON(http.StatusOK, filterProfiles(claims, targetUser)[0])
}
