package user

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/service/perm"
	"fdfz-student-id/internal/service/user"
	"fdfz-student-id/internal/util/validation"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/guregu/null/v6"
)

func getUserBanHandler(c *gin.Context) {
	claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)
	targetIDStr := c.Param("id")
	targetID, err := strconv.ParseInt(targetIDStr, 10, 64)
	if err != nil {
		errs.BadRequestError().AppendDetails("无效的用户 ID", "获取用户封禁信息失败").Respond(c)
		return
	}

	var allowed bool
	if targetID == claims.UserID {
		allowed = perm.Contains(claims.Permissions, "student_id.user.ban.read")
	} else {
		allowed = perm.Contains(claims.Permissions, "student_id.user.ban.read")
	}
	if !allowed {
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

type banUserReq struct {
	Reason  string    `json:"reason"`
	EndTime null.Time `json:"end_time"`
}

func banUserHandler(c *gin.Context) {
	claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)
	targetID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		errs.BadRequestError().AppendDetails("无效的用户 ID", "用户封禁失败").Respond(c)
		return
	}
	if targetID == claims.UserID {
		errs.BadRequestError().AppendDetails("不能封禁自己", "用户封禁失败").Respond(c)
		return
	}
	if !perm.Contains(claims.Permissions, "student_id.users.ban.create") {
		errs.PermissionDeniedError().AppendDetails("权限不足", "鉴权失败").Respond(c)
		return
	}

	var req banUserReq
	if err := c.ShouldBindJSON(&req); err != nil {
		errs.BadRequestError().AppendDetails("请求解析失败", "用户封禁失败").Respond(c)
		return
	}
	if err := validation.ValidateBanReason(req.Reason); err != nil {
		err.AppendDetails("用户封禁失败").Respond(c)
		return
	}
	if req.EndTime.Valid && !req.EndTime.Time.After(time.Now()) {
		errs.BadRequestError().AppendDetails("封禁结束时间必须晚于当前时间", "用户封禁失败").Respond(c)
		return
	}

	if target, uErr := user.GetUserByID(c.Request.Context(), targetID); uErr != nil {
		uErr.AppendDetails("用户封禁失败").Respond(c)
		return
	} else if target == nil {
		errs.NotFoundError().AppendDetails("用户不存在", "用户封禁失败").Respond(c)
		return
	}

	newBan := &model.UserBan{
		UserID:  targetID,
		Reason:  req.Reason,
		EndTime: req.EndTime,
	}
	if err := user.BanUser(c.Request.Context(), newBan); err != nil {
		err.AppendDetails("用户封禁失败").Respond(c)
		return
	}

	c.JSON(http.StatusOK, gin.H{})
}

func unbanUserHandler(c *gin.Context) {
	claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)
	targetID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		errs.BadRequestError().AppendDetails("无效的用户 ID", "用户解封失败").Respond(c)
		return
	}
	if !perm.Contains(claims.Permissions, "student_id.users.ban.delete") {
		errs.PermissionDeniedError().AppendDetails("权限不足", "鉴权失败").Respond(c)
		return
	}

	if target, uErr := user.GetUserByID(c.Request.Context(), targetID); uErr != nil {
		uErr.AppendDetails("用户解封失败").Respond(c)
		return
	} else if target == nil {
		errs.NotFoundError().AppendDetails("用户不存在", "用户解封失败").Respond(c)
		return
	}

	if err := user.UnbanUser(c.Request.Context(), targetID); err != nil {
		err.AppendDetails("用户解封失败").Respond(c)
		return
	}

	c.JSON(http.StatusOK, gin.H{})
}
