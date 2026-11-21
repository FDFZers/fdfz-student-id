package security

import (
	"fdfz-student-id/internal/errs"
	notificationsvc "fdfz-student-id/internal/service/notifications"
	usersvc "fdfz-student-id/internal/service/user"
	"fdfz-student-id/internal/util/handling"
	"net/http"

	"github.com/gin-gonic/gin"
)

// getTwoFactorSettingHandler 返回当前用户「登录二次验证」开关。
// 注意：该开关只影响登录时是否要求二次验证，提权等敏感操作仍按已绑定的方式校验。
func getTwoFactorSettingHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)

	usr, err := usersvc.GetUserByID(c.Request.Context(), claims.UserID)
	if err != nil {
		return err
	} else if usr == nil {
		return errs.NotFoundError().AppendDetails("用户不存在")
	}

	c.JSON(http.StatusOK, gin.H{"enabled": usr.TwoFactorEnabled})
	return nil
}

// twoFactorSettingReq 修改登录二次验证开关的请求体；enabled 必填，避免缺省值被误当成 false。
type twoFactorSettingReq struct {
	Enabled *bool `json:"enabled"`
}

// updateTwoFactorSettingHandler 修改当前用户的「登录二次验证」开关。
// 关闭后登录只需密码，修改密码、绑定方式、会话管理等敏感操作仍要求二次验证；
// 变更成功后会向用户已绑定的邮箱与 QQ 发送安全通知。
func updateTwoFactorSettingHandler(c *gin.Context) *errs.Error {
	var req twoFactorSettingReq
	if err := handling.BindJSON(c, &req); err != nil {
		return err
	}
	if req.Enabled == nil {
		return errs.BadRequestError().AppendDetails("缺少 enabled 参数")
	}

	claims := handling.MustGetClaims(c)
	ctx := c.Request.Context()

	usr, err := usersvc.GetUserByID(ctx, claims.UserID)
	if err != nil {
		return err
	} else if usr == nil {
		return errs.NotFoundError().AppendDetails("用户不存在")
	}

	// 值未变化时按幂等处理，不重复写库与发送通知
	if usr.TwoFactorEnabled != *req.Enabled {
		if err := usersvc.SetUserTwoFactorEnabled(ctx, claims.UserID, *req.Enabled); err != nil {
			return err
		}

		if *req.Enabled {
			notificationsvc.ToUser(ctx, claims.UserID, notificationsvc.NewTwoFactorEnabledMessage())
		} else {
			notificationsvc.ToUser(ctx, claims.UserID, notificationsvc.NewTwoFactorDisabledMessage())
		}
	}

	handling.RespondOK(c)
	return nil
}
