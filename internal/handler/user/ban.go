package user

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/service/perm"
	"fdfz-student-id/internal/service/user"
	"fdfz-student-id/internal/util/handling"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/guregu/null/v6"
)

func getUserBanHandler(c *gin.Context) *errs.Error {
	claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)
	targetIDStr := c.Param("id")
	targetID, e := strconv.ParseInt(targetIDStr, 10, 64)
	if e != nil {
		// 历史文案与其它分支不一致，Seal 以保持响应不变。
		return errs.BadRequestError().AppendDetails("无效的用户 ID", "获取用户封禁信息失败").Seal()
	}

	var allowed bool
	if targetID == claims.UserID {
		allowed = perm.Contains(claims.Permissions, "student_id.user.ban.read")
	} else {
		allowed = perm.Contains(claims.Permissions, "student_id.users.ban.read")
	}
	if !allowed {
		return errs.PermissionDeniedError().AppendDetails("权限不足", "鉴权失败").Seal()
	}

	ban, err := user.GetUserBan(c.Request.Context(), targetID)
	if err != nil {
		return err
	} else if ban == nil {
		c.JSON(http.StatusOK, gin.H{
			"banned": false,
		})
		return nil
	}

	c.JSON(http.StatusOK, gin.H{
		"banned":   true,
		"reason":   ban.Reason,
		"end_time": ban.EndTime,
	})
	return nil
}

type banUserReq struct {
	Reason  string    `json:"reason"`
	EndTime null.Time `json:"end_time"`
}

func banUserHandler(c *gin.Context) *errs.Error {
	claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)
	targetID, err := ResolveTargetID(c, claims.UserID)
	if err != nil {
		return err
	}
	if targetID == claims.UserID {
		return errs.BadRequestError().AppendDetails("不能封禁自己")
	}
	if !perm.Contains(claims.Permissions, "student_id.users.ban.create") {
		return errs.PermissionDeniedError().AppendDetails("权限不足", "鉴权失败").Seal()
	}

	var req banUserReq
	if err := c.ShouldBindJSON(&req); err != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}
	if err := handling.ValidateBanReason(req.Reason); err != nil {
		return err
	}
	if req.EndTime.Valid && !req.EndTime.Time.After(time.Now()) {
		return errs.BadRequestError().AppendDetails("封禁结束时间必须晚于当前时间")
	}

	if err := EnsureUserExists(c, targetID); err != nil {
		return err
	}

	newBan := &model.UserBan{
		UserID:  targetID,
		Reason:  req.Reason,
		EndTime: req.EndTime,
	}
	if err := user.BanUser(c.Request.Context(), newBan); err != nil {
		return err
	}

	c.JSON(http.StatusOK, gin.H{})
	return nil
}

func unbanUserHandler(c *gin.Context) *errs.Error {
	claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)
	targetID, err := ResolveTargetID(c, claims.UserID)
	if err != nil {
		return err
	}
	if !perm.Contains(claims.Permissions, "student_id.users.ban.delete") {
		return errs.PermissionDeniedError().AppendDetails("权限不足", "鉴权失败").Seal()
	}

	if err := EnsureUserExists(c, targetID); err != nil {
		return err
	}

	if err := user.UnbanUser(c.Request.Context(), targetID); err != nil {
		return err
	}

	c.JSON(http.StatusOK, gin.H{})
	return nil
}
