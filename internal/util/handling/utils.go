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

// MustGetClaims 取出 ParseToken 中间件写入的令牌声明。
// 注意：仅在 RequireToken 等中间件保证 claims 存在的路由中调用，claims 缺失时会 panic。
func MustGetClaims(c *gin.Context) *model.RegisteredTokenClaims {
	return c.MustGet("token_claims").(*model.RegisteredTokenClaims)
}

// GetClaimsOrNil 取出令牌声明；未提供或类型不符时返回 nil，不会 panic。
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

// ParseID 读取路径参数 name 并解析为正整数 ID。
// item 是日志/文案中的资源名（如「用户组」），用于拼出「用户组 ID 格式错误」。
func ParseID(c *gin.Context, name, item string) (int64, *errs.Error) {
	raw := c.Param(name)
	if raw == "" {
		return 0, errs.BadRequestError().AppendDetails("未提供" + item + " ID")
	}
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		return 0, errs.BadRequestError().AppendDetails(item + " ID 格式错误")
	}
	return id, nil
}

// ParseUserID 解析可选的目标用户 ID：param 为空时返回 selfID（表示操作自己）。
// 与 ParseID 保持一致：显式传入的 ID 必须是正整数，0/负数返回 400。
func ParseUserID(c *gin.Context, selfID int64, param string) (int64, *errs.Error) {
	str := c.Param(param)
	if str == "" {
		return selfID, nil
	}
	id, err := strconv.ParseInt(str, 10, 64)
	if err != nil || id <= 0 {
		return 0, errs.BadRequestError().AppendDetails("用户 ID 格式错误")
	}
	return id, nil
}

// ResolveApp 解析路径参数 appID 并查询对应的 OAuth 应用（应用注册表）。
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

// EnsureUserExists 确认目标用户存在，不存在时返回 404。常用于「操作的别人」的场景。
func EnsureUserExists(c *gin.Context, userID int64) *errs.Error {
	target, err := user.GetUserByID(c.Request.Context(), userID)
	if err != nil {
		return err
	} else if target == nil {
		return errs.NotFoundError().AppendDetails("用户不存在")
	}
	return nil
}

// CookieDomain 返回令牌 Cookie 使用的域名：生产环境为 .fdfz.top，本地为 .ffhub.localhost。
func CookieDomain() string {
	if cfg.IsProd {
		return ".fdfz.top"
	}
	return ".ffhub.localhost"
}

// BannedError 把封禁记录转换为 403 错误，details 说明封禁原因与解封时间。
func BannedError(ban *model.UserBan) *errs.Error {
	if ban.EndTime.Valid {
		return errs.PermissionDeniedError().AppendDetails(
			fmt.Sprintf("用户已被封禁：%s（解封时间：%s）", ban.Reason, ban.EndTime.Time.Format("2006-01-02 15:04:05")),
		)
	}
	return errs.PermissionDeniedError().AppendDetails(
		fmt.Sprintf("用户已被永久封禁：%s", ban.Reason),
	)
}

// SetTokenCookies 写入访问令牌与刷新用 session token 两个 Cookie。
// 注意：access_token 供前端读取（HttpOnly=false），session_token 仅供刷新接口使用（HttpOnly=true）。
func SetTokenCookies(c *gin.Context, accessToken, sessionToken string, accessMaxAge, sessionMaxAge int) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("access_token", accessToken, accessMaxAge, "/", CookieDomain(), cfg.IsProd, false)
	c.SetCookie("session_token", sessionToken, sessionMaxAge, "/", CookieDomain(), cfg.IsProd, true)
}

// SetStepupCookie 写入提权令牌 Cookie（HttpOnly），用于二次验证后执行敏感操作。
// 注意：Secure 与其它令牌 Cookie 保持一致，仅生产环境开启，否则本地 http 调试时浏览器不会携带该 Cookie。
func SetStepupCookie(c *gin.Context, token string, maxAge int) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("stepup_token", token, maxAge, "/", CookieDomain(), cfg.IsProd, true)
}

// ClearSessionCookies 清除访问令牌、session token 与提权令牌 Cookie（登出时使用）。
func ClearSessionCookies(c *gin.Context) {
	SetTokenCookies(c, "", "", -1, -1)
	SetStepupCookie(c, "", -1)
}

// ClearStepupCookie 清除提权令牌 Cookie。
func ClearStepupCookie(c *gin.Context) {
	SetStepupCookie(c, "", -1)
}
