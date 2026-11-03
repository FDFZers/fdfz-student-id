package handling

import (
	"fdfz-student-id/internal/cfg"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	appsvc "fdfz-student-id/internal/service/app"
	"fdfz-student-id/internal/service/user"
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

func MustGetClaims(c *gin.Context) *model.RegisteredTokenClaims {
	return c.MustGet("token_claims").(*model.RegisteredTokenClaims)
}

func GetClaimsOrNil(c *gin.Context) *model.RegisteredTokenClaims {
	value, exists := c.Get("token_claims")
	if !exists {
		return nil
	}
	claims, ok := value.(*model.RegisteredTokenClaims)
	if !ok || claims == nil {
		return nil
	}
	return claims
}

func ParseID(c *gin.Context, name, item string) (int64, *errs.Error) {
	id, err := strconv.ParseInt(c.Param(name), 10, 64)
	if err != nil || id <= 0 {
		return 0, errs.BadRequestError().AppendDetails("无效的" + item + " ID")
	}
	return id, nil
}

func ParseUserID(c *gin.Context, selfID int64, param string) (int64, *errs.Error) {
	str := c.Param(param)
	if str == "" {
		return selfID, nil
	}
	id, err := strconv.ParseInt(str, 10, 64)
	if err != nil {
		return 0, errs.BadRequestError().AppendDetails("无效的用户 ID")
	}
	return id, nil
}

func ResolveApp(c *gin.Context) (*model.OAuthApp, *errs.Error) {
	appID, err := ParseID(c, "appID", "应用")
	if err != nil {
		return nil, err
	}
	app, err := appsvc.GetAppByID(c.Request.Context(), appID)
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, errs.NotFoundError().AppendDetails("应用不存在")
	}
	return app, nil
}

func EnsureUserExists(c *gin.Context, userID int64) *errs.Error {
	target, err := user.GetUserByID(c.Request.Context(), userID)
	if err != nil {
		return err
	} else if target == nil {
		return errs.NotFoundError().AppendDetails("用户不存在")
	}
	return nil
}

func CookieDomain() string {
	if cfg.IsProd {
		return ".fdfz.top"
	}
	return ".ffhub.localhost"
}

func BannedError(ban *model.UserBan) *errs.Error {
	if ban.EndTime.Valid {
		return errs.PermissionDeniedError().AppendDetails(
			fmt.Sprintf("用户已封禁：%s（%s）", ban.Reason, ban.EndTime.Time.Format("2006-01-02 15:04:05")),
		)
	}
	return errs.PermissionDeniedError().AppendDetails(
		fmt.Sprintf("用户已永久封禁：%s", ban.Reason),
	)
}

func SetTokenCookies(c *gin.Context, accessToken, sessionToken string, accessMaxAge, sessionMaxAge int) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("access_token", accessToken, accessMaxAge, "/", CookieDomain(), cfg.IsProd, false)
	c.SetCookie("session_token", sessionToken, sessionMaxAge, "/", CookieDomain(), cfg.IsProd, true)
}

func SetStepupCookie(c *gin.Context, token string, maxAge int) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("stepup_token", token, maxAge, "/", CookieDomain(), true, true)
}

func ClearSessionCookies(c *gin.Context) {
	SetTokenCookies(c, "", "", -1, -1)
	SetStepupCookie(c, "", -1)
}

func ClearStepupCookie(c *gin.Context) {
	SetStepupCookie(c, "", -1)
}
