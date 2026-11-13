package app

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/middleware"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/service/perm"
	"fdfz-student-id/internal/util/handling"
	"net/http"

	"github.com/gin-gonic/gin"
)

// InitRoutes 注册 OAuth 应用管理路由：/api/internal 下的管理接口，以及对外公开的图标读取接口。
func InitRoutes(api, internal *gin.RouterGroup) {
	group := internal.Group("/app")

	// 创建应用、停用/启用仅管理员可用；删除允许全局删除权限或应用所有者删除自己的应用。
	group.POST("", middleware.RequirePermission(perm.PermAppsCreate), handling.Wrap("OAuth 应用创建失败", createAppHandler))
	group.POST("/:appID/suspend", middleware.RequirePermission(perm.PermAppsSuspend), handling.Wrap("OAuth 应用停用失败", suspendAppHandler))
	group.POST("/:appID/activate", middleware.RequirePermission(perm.PermAppsSuspend), handling.Wrap("OAuth 应用启用失败", activateAppHandler))
	group.DELETE("/:appID", middleware.RequireToken(), handling.Wrap("OAuth 应用删除失败", deleteAppHandler))

	// 搜索、详情、修改、密钥与图标：管理员可操作全部应用，应用所有者可操作自己的应用。
	group.GET("/search/info", middleware.RequireToken(), handling.Wrap("应用搜索信息获取失败", appSearchInfoHandler))
	group.POST("/search/query", middleware.RequireToken(), handling.Wrap("应用搜索失败", appSearchQueryHandler))
	group.GET("/:appID", middleware.RequireToken(), handling.Wrap("OAuth 应用获取失败", getAppHandler))
	group.PATCH("/:appID", middleware.RequireToken(), handling.Wrap("OAuth 应用修改失败", updateAppHandler))
	group.POST("/:appID/secret/rotate", middleware.RequireToken(), handling.Wrap("OAuth 应用密钥重置失败", rotateSecretHandler))
	group.PUT("/:appID/icon", middleware.RequireToken(), middleware.LimitSize(5<<20), handling.Wrap("OAuth 应用图标设置失败", setIconHandler))
	group.DELETE("/:appID/icon", middleware.RequireToken(), handling.Wrap("OAuth 应用图标删除失败", deleteIconHandler))

	// 图标需要出现在 OAuth 授权页等公开页面，走无需令牌的对外接口。
	api.GET("/app/:appID/icon", handling.Wrap("OAuth 应用图标获取失败", getIconHandler))
}

// managedApp 解析路径参数 appID 并校验应用管理权限：
// 全局管理员使用 apps.list 读取全部应用、使用 apps.update 修改全部应用；
// 应用所有者使用 app.read/app.update，且应用必须归属于当前用户。
// write 为 true 时要求写权限，否则要求读权限。
func managedApp(c *gin.Context, write bool) (*model.OAuthApp, *errs.Error) {
	claims := handling.MustGetClaims(c)

	var isGlobal, hasOwnedPermission bool
	if write {
		isGlobal = handling.IsGlobalAppAdmin(claims)
		hasOwnedPermission = perm.HasPermission(claims, perm.PermAppUpdate)
	} else {
		isGlobal = handling.IsGlobalAppReader(claims)
		hasOwnedPermission = perm.HasPermission(claims, perm.PermAppRead)
	}
	if !isGlobal && !hasOwnedPermission {
		return nil, errs.PermissionDeniedError().AppendDetails("权限不足").Seal()
	}

	a, err := handling.ResolveApp(c)
	if err != nil {
		return nil, err
	}
	if !isGlobal && a.OwnerUserID != claims.UserID {
		return nil, errs.PermissionDeniedError().AppendDetails("权限不足").Seal()
	}
	return a, nil
}

// appJSON 把应用渲染为 API 响应；不暴露密钥哈希，仅返回是否已设置密钥。
func appJSON(a *model.OAuthApp) gin.H {
	data := gin.H{
		"id":              a.ID,
		"namespace":       a.Namespace,
		"owner_user_id":   a.OwnerUserID,
		"name":            a.Name,
		"description":     a.Description,
		"homepage_url":    a.HomepageURL,
		"client_type":     a.ClientType,
		"redirect_uris":   a.RedirectURIs,
		"requested_perms": a.RequestedPerms,
		"status":          a.Status,
		"has_secret":      a.ClientType.IsConfidential() && a.SecretHash.Valid,
		"created_at":      a.CreatedAt,
		"updated_at":      a.UpdatedAt,
	}
	return data
}

// appsJSON 把应用列表渲染为数组。
func appsJSON(apps []*model.OAuthApp) []gin.H {
	data := make([]gin.H, 0, len(apps))
	for _, a := range apps {
		data = append(data, appJSON(a))
	}
	return data
}

// dedupeStrings 按首次出现顺序去重，空列表返回空切片而不是 nil。
func dedupeStrings(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	result := make([]string, 0, len(items))
	for _, item := range items {
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		result = append(result, item)
	}
	return result
}

// respondApp 写出单个应用响应。
func respondApp(c *gin.Context, a *model.OAuthApp) {
	c.JSON(http.StatusOK, appJSON(a))
}
