package security

import (
	"net/http"

	"fdfz-student-id/internal/errs"
	notificationsvc "fdfz-student-id/internal/service/notifications"
	usersvc "fdfz-student-id/internal/service/user"
	"fdfz-student-id/internal/util/handling"

	"github.com/gin-gonic/gin"
)

func getAppNotificationsSettingHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)

	usr, err := usersvc.GetUserByID(c.Request.Context(), claims.UserID)
	if err != nil {
		return err
	} else if usr == nil {
		return errs.NotFoundError().AppendDetails("用户不存在")
	}

	c.JSON(http.StatusOK, gin.H{"enabled": usr.AppNotificationsEnabled})
	return nil
}

// appNotificationsSettingReq 修改应用通知总开关的请求体，enabled 必填。
type appNotificationsSettingReq struct {
	Enabled *bool `json:"enabled"`
}

// updateAppNotificationsSettingHandler 修改应用通知总开关；关闭后即使应用已获授权也不能发送。
func updateAppNotificationsSettingHandler(c *gin.Context) *errs.Error {
	var req appNotificationsSettingReq
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

	// 值未变化时按幂等处理，不重复发送通知
	if usr.AppNotificationsEnabled != *req.Enabled {
		if err := usersvc.SetUserAppNotificationsEnabled(ctx, claims.UserID, *req.Enabled); err != nil {
			return err
		}
		notificationsvc.ToUser(ctx, claims.UserID, notificationsvc.NewAppNotificationsSettingMessage(*req.Enabled))
	}

	handling.RespondOK(c)
	return nil
}
