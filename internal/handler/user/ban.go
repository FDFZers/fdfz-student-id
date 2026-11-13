package user

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/service/perm"
	"fdfz-student-id/internal/service/user"
	"fdfz-student-id/internal/util/handling"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/guregu/null/v6"
)

// getUserBanHandler 查询指定用户的封禁信息：未登录不可调用，需带令牌。
// 查自己需要 user.ban.read，查他人需要 users.ban.read；无封禁时返回 banned=false。
func getUserBanHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)
	targetID, err := handling.ParseID(c, "id", "用户")
	if err != nil {
		return err
	}

	// 先判权限再查存在性，避免用 404/403 差异探测用户是否存在。

	var allowed bool
	if targetID == claims.UserID {
		allowed = perm.HasPermission(claims, perm.PermUserBanRead)
	} else {
		allowed = perm.HasPermission(claims, perm.PermUsersBanRead)
	}
	if !allowed {
		return errs.PermissionDeniedError().AppendDetails("权限不足").Seal()
	}

	if err := handling.EnsureUserExists(c, targetID); err != nil {
		return err
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

// banUserReq 封禁请求体；end_time 为空表示永久封禁。
type banUserReq struct {
	Reason  string    `json:"reason"`
	EndTime null.Time `json:"end_time"`
}

// banUserHandler 封禁指定用户并记录审计日志；不能封禁自己或拥有写权限的账号。
func banUserHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)
	targetID, err := handling.ParseUserID(c, claims.UserID, "id")
	if err != nil {
		return err
	}
	if targetID == claims.UserID {
		return errs.BadRequestError().AppendDetails("不能封禁自己")
	}

	// 校验请求体与封禁原因、结束时间

	var req banUserReq
	if e := c.ShouldBindJSON(&req); e != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}
	if err := handling.ValidateBanReason(req.Reason); err != nil {
		return err
	}
	if req.EndTime.Valid {
		if err := handling.ValidateFutureTime(req.EndTime.Time, "封禁结束时间"); err != nil {
			return err
		}
	}

	if err := handling.EnsureUserExists(c, targetID); err != nil {
		return err
	}

	hasWritePermission, err := handling.UserHasWritePerm(c.Request.Context(), targetID)
	if err != nil {
		return err
	}
	if hasWritePermission {
		return errs.PermissionDeniedError().AppendDetails("不能封禁拥有写权限的用户")
	}

	// 写入封禁记录并输出审计日志

	newBan := &model.UserBan{
		UserID:  targetID,
		Reason:  req.Reason,
		EndTime: req.EndTime,
	}
	if err := user.BanUser(c.Request.Context(), newBan); err != nil {
		return err
	}

	attrs := []any{
		"user_id", targetID,
		"operator_id", claims.UserID,
		"reason", req.Reason,
	}
	if req.EndTime.Valid {
		attrs = append(attrs, "end_time", req.EndTime.Time)
	}
	slog.Info("User banned", attrs...)

	c.JSON(http.StatusOK, gin.H{})
	return nil
}

// unbanUserHandler 解除指定用户的封禁：确认目标用户存在后禁用其启用中的封禁记录。
// 注意：不能解封自己；对未封禁用户执行不会报错（幂等）。
func unbanUserHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)
	targetID, err := handling.ParseUserID(c, claims.UserID, "id")
	if err != nil {
		return err
	}
	if targetID == claims.UserID {
		return errs.BadRequestError().AppendDetails("不能解封自己")
	}

	if err := handling.EnsureUserExists(c, targetID); err != nil {
		return err
	}

	if err := user.UnbanUser(c.Request.Context(), targetID); err != nil {
		return err
	}

	slog.Info("User unbanned", "user_id", targetID, "operator_id", claims.UserID)

	c.JSON(http.StatusOK, gin.H{})
	return nil
}
