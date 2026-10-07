package user

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/perm"
	"fdfz-student-id/internal/service/user"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

func getUserBanHandler(c *gin.Context) {
	claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)
	targetIDStr := c.Param("id")
	targetID, err := strconv.ParseInt(targetIDStr, 10, 64)
	if err != nil {
		errs.BadRequestError().AppendDetails("无效的用户 ID", "获取用户封禁信息失败").Respond(c)
		return
	}

	hasSelfPerm := targetID == claims.UserID && perm.Contains(claims.Permissions, "student_id.user.profile.ban.read.self")
	hasPerm := hasSelfPerm || perm.ContainsAny(claims.Permissions, "student_id.user.profile.public.read", "student_id.user.profile.ban.read")
	if !hasPerm {
		errs.PermissionDeniedError().AppendDetails("权限不足", "鉴权失败").Respond(c)
		return
	}

	ban, uErr := user.GetUserBan(c.Request.Context(), targetID)
	if uErr != nil {
		uErr.AppendDetails("用户封禁信息获取失败").Respond(c)
		return
	} else if ban == nil {
		c.JSON(http.StatusOK, gin.H{
			"banned": false,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"banned":   true,
		"reason":   ban.Reason,
		"end_time": ban.EndTime,
	})
}
