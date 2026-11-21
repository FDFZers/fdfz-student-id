package oauth

import (
	"net/http"

	"fdfz-student-id/internal/errs"
	notificationsvc "fdfz-student-id/internal/service/notifications"
	oauthsvc "fdfz-student-id/internal/service/oauth"
	"fdfz-student-id/internal/util/handling"

	"github.com/gin-gonic/gin"
)

type deviceCreateRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

func deviceCreateHandler(c *gin.Context) *errs.Error {
	var req deviceCreateRequest
	if err := handling.BindJSON(c, &req); err != nil {
		return err
	}

	app, err := oauthsvc.AuthenticateClient(c.Request.Context(), req.ClientID, req.ClientSecret)
	if err != nil {
		return err
	}

	response, err := oauthsvc.StartDeviceAuthorization(c.Request.Context(), app)
	if err != nil {
		return err
	}

	c.JSON(http.StatusOK, response)
	return nil
}

func devicePreviewHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)

	preview, err := oauthsvc.GetDeviceAuthorization(c.Request.Context(), claims.UserID, c.Query("user_code"))
	if err != nil {
		return err
	}

	c.JSON(http.StatusOK, preview)
	return nil
}

// deviceApproveRequest 提交设备授权决策；授予应用登记的全部可授予权限。
type deviceApproveRequest struct {
	UserCode           string `json:"user_code"`
	Approve            *bool  `json:"approve"`
	AllowNotifications *bool  `json:"allow_notifications"` // 缺省沿用已有授权的设置
}

func deviceApproveHandler(c *gin.Context) *errs.Error {
	var req deviceApproveRequest
	if err := handling.BindJSON(c, &req); err != nil {
		return err
	}
	if req.UserCode == "" {
		return errs.BadRequestError().AppendDetails("缺少 user_code")
	}
	if req.Approve == nil {
		return errs.BadRequestError().AppendDetails("缺少授权决定")
	}

	claims := handling.MustGetClaims(c)

	result, err := oauthsvc.DecideDeviceAuthorization(
		c.Request.Context(), claims.UserID, req.UserCode, *req.Approve, req.AllowNotifications,
	)
	if err != nil {
		return err
	}

	if result.Approved && result.App != nil {
		notificationsvc.ToUser(c.Request.Context(), claims.UserID, notificationsvc.NewOAuthDeviceAuthorizedMessage(
			result.App.Name, result.Permissions, result.AllowNotifications,
		))
	}

	handling.RespondOK(c)
	return nil
}
