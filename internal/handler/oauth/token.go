package oauth

import (
	"net/http"

	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
	oauthsvc "fdfz-student-id/internal/service/oauth"
	"fdfz-student-id/internal/util/handling"

	"github.com/gin-gonic/gin"
)

type tokenRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Code         string `json:"code"`
	CodeVerifier string `json:"code_verifier"` // 可选，授权时使用了 PKCE 才需要
	RedirectURI  string `json:"redirect_uri"`  // 发起授权时显式传了 redirect_uri 的话必须原样回传
}

func tokenHandler(c *gin.Context) *errs.Error {
	var req tokenRequest
	if err := handling.BindJSON(c, &req); err != nil {
		return err
	}

	app, err := oauthsvc.AuthenticateClient(c.Request.Context(), req.ClientID, req.ClientSecret)
	if err != nil {
		return err
	}

	response, err := oauthsvc.ExchangeAuthorizationCode(c.Request.Context(), app, req.Code, req.CodeVerifier, req.RedirectURI)
	if err != nil {
		return err
	}

	c.JSON(http.StatusOK, response)
	return nil
}

type refreshRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RefreshToken string `json:"refresh_token"`
}

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

type deviceTokenRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	DeviceCode   string `json:"device_code"`
}

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

type revokeRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RefreshToken string `json:"refresh_token"`
}

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
