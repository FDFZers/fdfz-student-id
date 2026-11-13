package oauth

import (
	"net/http"

	"fdfz-student-id/internal/errs"
	oauthsvc "fdfz-student-id/internal/service/oauth"
	"fdfz-student-id/internal/util/handling"

	"github.com/gin-gonic/gin"
)

// deviceCreateRequest 是创建设备授权请求的请求体。
type deviceCreateRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Permission   string `json:"permission"` // 空格或逗号分隔的权限串，省略时使用应用登记的全部权限
}

// deviceCreateHandler 创建设备码与用户短码，供设备轮询与用户确认。
func deviceCreateHandler(c *gin.Context) *errs.Error {
	var req deviceCreateRequest
	if err := handling.BindJSON(c, &req); err != nil {
		return err
	}

	app, err := oauthsvc.AuthenticateClient(c.Request.Context(), req.ClientID, req.ClientSecret)
	if err != nil {
		return err
	}

	response, err := oauthsvc.StartDeviceAuthorization(c.Request.Context(), app, req.Permission)
	if err != nil {
		return err
	}

	c.JSON(http.StatusOK, response)
	return nil
}

// devicePreviewHandler 按 user_code 返回设备授权请求详情，供确认页展示。
func devicePreviewHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)

	preview, err := oauthsvc.GetDeviceAuthorization(c.Request.Context(), claims.UserID, c.Query("user_code"))
	if err != nil {
		return err
	}

	c.JSON(http.StatusOK, preview)
	return nil
}

// deviceApproveRequest 是设备确认页的提交体。
// permissions 为 nil 表示授予全部可授予权限；为空数组表示一项都不授予。
type deviceApproveRequest struct {
	UserCode    string    `json:"user_code"`
	Approve     *bool     `json:"approve"`
	Permissions *[]string `json:"permissions"`
}

// deviceApproveHandler 处理设备授权请求的同意/拒绝操作。
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
	var permissions []string
	if req.Permissions != nil {
		permissions = *req.Permissions
	}

	if err := oauthsvc.DecideDeviceAuthorization(
		c.Request.Context(), claims.UserID, req.UserCode, *req.Approve, permissions,
	); err != nil {
		return err
	}

	handling.RespondOK(c)
	return nil
}
