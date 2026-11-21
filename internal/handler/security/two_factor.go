package security

import (
	"fdfz-student-id/internal/errs"
	notifysvc "fdfz-student-id/internal/service/notify"
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
			notifysvc.ToUser(ctx, claims.UserID, notifysvc.NewMessage(
				"登录二次验证已开启",
				"你的账号已开启登录二次验证",
				"你好！你的复旦附中学生 ID 账号已于北京时间 "+notifysvc.BeijingTime()+" 开启登录二次验证。",
				"之后登录时需要使用已绑定的邮箱、QQ 或 TOTP 完成二次验证。如非本人操作，请立即修改密码并检查账号安全。",
			))
		} else {
			notifysvc.ToUser(ctx, claims.UserID, notifysvc.NewMessage(
				"登录二次验证已关闭",
				"你的账号已关闭登录二次验证",
				"你好！你的复旦附中学生 ID 账号已于北京时间 "+notifysvc.BeijingTime()+" 关闭登录二次验证。",
				"关闭后登录只需密码；修改密码、绑定方式与会话管理等敏感操作仍要求二次验证。如非本人操作，请立即修改密码并检查账号安全。",
			))
		}
	}

	handling.RespondOK(c)
	return nil
}
