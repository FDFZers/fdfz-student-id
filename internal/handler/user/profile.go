package user

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/service/user"
	"net/http"

	"github.com/gin-gonic/gin"
)

func getUserProfileByUsernameHandler(c *gin.Context) *errs.Error {
	claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)
	targetUsername := c.Param("username")

	targetUser, err := user.GetUserByUsername(c.Request.Context(), targetUsername)
	if err != nil {
		return err
	} else if targetUser == nil {
		return errs.NotFoundError().AppendDetails("用户不存在")
	}
	c.JSON(http.StatusOK, filterProfiles(claims, targetUser)[0])
	return nil
}

func getUserProfileByIDHandler(c *gin.Context) *errs.Error {
	claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)
	targetID, err := ResolveTargetID(c, claims.UserID)
	if err != nil {
		return err
	}

	targetUser, err := user.GetUserByID(c.Request.Context(), targetID)
	if err != nil {
		return err
	} else if targetUser == nil {
		return errs.NotFoundError().AppendDetails("用户不存在")
	}
	c.JSON(http.StatusOK, filterProfiles(claims, targetUser)[0])
	return nil
}
