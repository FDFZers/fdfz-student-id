package app

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/middleware"
	"fdfz-student-id/internal/model"
	permsvc "fdfz-student-id/internal/service/perm"
	"fdfz-student-id/internal/util/handling"
	"net/http"

	"github.com/gin-gonic/gin"
)

// InitRoutes 注册 OAuth 应用管理路由。
func InitRoutes(api, internal *gin.RouterGroup) {
	group := internal.Group("/app")

	// 创建应用、停用/启用仅管理员可用；删除允许全局删除权限或应用所有者删除自己的应用。
	group.POST("", middleware.RequirePermission(permsvc.PermAppsCreate), handling.Wrap("OAuth 应用创建失败", createAppHandler))
	group.POST("/:appID/suspend", middleware.RequirePermission(permsvc.PermAppsSuspend), handling.Wrap("OAuth 应用停用失败", suspendAppHandler))
	group.POST("/:appID/activate", middleware.RequirePermission(permsvc.PermAppsSuspend), handling.Wrap("OAuth 应用启用失败", activateAppHandler))
	group.DELETE("/:appID", middleware.RequireToken(), handling.Wrap("OAuth 应用删除失败", deleteAppHandler))

	// 搜索、详情、修改、密钥与图标：管理员可操作全部应用，应用所有者可操作自己的应用。
	group.GET("/search/info", middleware.RequireToken(), handling.Wrap("应用搜索信息获取失败", appSearchInfoHandler))
	group.POST("/search/query", middleware.RequireToken(), handling.Wrap("应用搜索失败", appSearchQueryHandler))
	group.GET("/:appID", middleware.RequireToken(), handling.Wrap("OAuth 应用获取失败", getAppHandler))
	group.PATCH("/:appID", middleware.RequireToken(), handling.Wrap("OAuth 应用修改失败", updateAppHandler))
	group.POST("/:appID/secret/rotate", middleware.RequireToken(), handling.Wrap("OAuth 应用密钥重置失败", rotateSecretHandler))
	group.PUT("/:appID/icon", middleware.RequireToken(), middleware.LimitSize(5<<20), handling.Wrap("OAuth 应用图标设置失败", setIconHandler))
	group.DELETE("/:appID/icon", middleware.RequireToken(), handling.Wrap("OAuth 应用图标删除失败", deleteIconHandler))

	// 用户授权管理：查看/撤销自己授予应用的权限；oauths.* 可管理他人。
	// internal 组已拒绝 OAuth 令牌，stepup 令牌由处理器内的权限检查拒绝。
	group.GET("/authorizations", middleware.RequireToken(), handling.Wrap("授权列表获取失败", listAuthorizationsHandler))
	group.GET("/authorizations/:id", middleware.RequireToken(), handling.Wrap("授权列表获取失败", listAuthorizationsHandler))
	group.DELETE("/authorizations/:authID", middleware.RequireToken(), handling.Wrap("授权撤销失败", revokeAuthorizationHandler))

	// 图标需要出现在 OAuth 授权页等公开页面，走无需令牌的对外接口。
	api.GET("/app/:appID/icon", handling.Wrap("OAuth 应用图标获取失败", getIconHandler))
}

// managedApp 解析路径中的 appID 并校验应用管理权限。
func managedApp(c *gin.Context, write bool) (*model.OAuthApp, *errs.Error) {
	claims := handling.MustGetClaims(c)

	var isGlobal, hasOwnedPermission bool
	if write {
		isGlobal = handling.IsGlobalAppAdmin(claims)
		hasOwnedPermission = permsvc.HasPermission(claims, permsvc.PermAppUpdate)
	} else {
		isGlobal = handling.IsGlobalAppReader(claims)
		hasOwnedPermission = permsvc.HasPermission(claims, permsvc.PermAppRead)
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

func respondApp(c *gin.Context, a *model.OAuthApp) {
	c.JSON(http.StatusOK, handling.AppJSON(a))
}
