package oauth

import (
	"net/http"

	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
	oauthsvc "fdfz-student-id/internal/service/oauth"
	"fdfz-student-id/internal/util/handling"

	"github.com/gin-gonic/gin"
)

// tokenRequest 是授权码换令牌的请求体。
type tokenRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Code         string `json:"code"`
	CodeVerifier string `json:"code_verifier"` // 可选，授权时使用了 PKCE 才需要
}

// tokenHandler 用授权码换取访问令牌与刷新令牌。
func tokenHandler(c *gin.Context) *errs.Error {
	var req tokenRequest
	if err := handling.BindJSON(c, &req); err != nil {
		return err
	}

	app, err := oauthsvc.AuthenticateClient(c.Request.Context(), req.ClientID, req.ClientSecret)
	if err != nil {
		return err
	}

	response, err := oauthsvc.ExchangeAuthorizationCode(c.Request.Context(), app, req.Code, req.CodeVerifier)
	if err != nil {
		return err
	}

	c.JSON(http.StatusOK, response)
	return nil
}

// refreshRequest 是刷新令牌的请求体。
type refreshRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RefreshToken string `json:"refresh_token"`
}

// refreshHandler 轮换刷新令牌并换发新的访问令牌。
func refreshHandler(c *gin.Context) *errs.Error {
	var req refreshRequest
	if err := handling.BindJSON(c, &req); err != nil {
		return err
	}

	app, err := oauthsvc.AuthenticateClient(c.Request.Context(), req.ClientID, req.ClientSecret)
	if err != nil {
		return err
	}

	response, err := oauthsvc.ExchangeRefreshToken(c.Request.Context(), db.R, app, req.RefreshToken)
	if err != nil {
		return err
	}

	c.JSON(http.StatusOK, response)
	return nil
}

// deviceTokenRequest 是设备轮询的请求体。
type deviceTokenRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	DeviceCode   string `json:"device_code"`
}

// deviceTokenHandler 返回设备轮询状态；批准时直接返回令牌。
func deviceTokenHandler(c *gin.Context) *errs.Error {
	var req deviceTokenRequest
	if err := handling.BindJSON(c, &req); err != nil {
		return err
	}

	app, err := oauthsvc.AuthenticateClient(c.Request.Context(), req.ClientID, req.ClientSecret)
	if err != nil {
		return err
	}

	response, err := oauthsvc.ExchangeDeviceCode(c.Request.Context(), app, req.DeviceCode)
	if err != nil {
		return err
	}

	c.JSON(http.StatusOK, response)
	return nil
}

// revokeRequest 是吊销刷新令牌的请求体。
type revokeRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RefreshToken string `json:"refresh_token"`
}

// revokeHandler 吊销客户端自己的刷新令牌，始终返回成功。
func revokeHandler(c *gin.Context) *errs.Error {
	var req revokeRequest
	if err := handling.BindJSON(c, &req); err != nil {
		return err
	}

	app, err := oauthsvc.AuthenticateClient(c.Request.Context(), req.ClientID, req.ClientSecret)
	if err != nil {
		return err
	}

	if err := oauthsvc.RevokeRefreshToken(c.Request.Context(), app, req.RefreshToken); err != nil {
		return err
	}

	handling.RespondOK(c)
	return nil
}
