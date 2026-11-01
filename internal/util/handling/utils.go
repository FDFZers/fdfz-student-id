package handling

import (
	"fdfz-student-id/internal/cfg"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

func CookieDomain() string {
	if cfg.IsProd {
		return ".fdfz.top"
	}
	return ".ffhub.localhost"
}

// BannedError 构造“用户已被封禁”错误，失败动作名由 handler 包装器统一追加。
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
	SetTokenCookies(c, "", "", 0, 0)
	SetStepupCookie(c, "", -1)
}
