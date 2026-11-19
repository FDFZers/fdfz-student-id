package permissions

import (
	"fdfz-student-id/internal/middleware"
	permsvc "fdfz-student-id/internal/service/perm"
	"fdfz-student-id/internal/util/handling"

	"github.com/gin-gonic/gin"
)

// InitRoutes 在 /permissions 下注册权限管理相关路由。
// 应用维度接口用 RequireAppAccess 鉴权：拥有全局权限，或拥有应用所有者权限且是该应用所有者；
// 全局维度接口用 RequirePermission 鉴权。
func InitRoutes(internal *gin.RouterGroup) {
	group := internal.Group("/permissions")

	appRead := middleware.RequireAppAccess("appID", permsvc.PermPermissionsRead, permsvc.PermPermissionRead)
	appWrite := middleware.RequireAppAccess("appID", permsvc.PermPermissionsWrite, permsvc.PermPermissionWrite)
	globalRead := middleware.RequirePermission(permsvc.PermPermissionsRead)
	globalWrite := middleware.RequirePermission(permsvc.PermPermissionsWrite)

	// 应用维度的权限定义与继承
	group.GET("/:appID/definitions/search/info", appRead, handling.Wrap("权限定义搜索信息获取失败", appPermissionSearchInfoHandler))
	group.POST("/:appID/definitions/search/query", appRead, handling.Wrap("权限定义搜索失败", appPermissionSearchQueryHandler))
	group.POST("/:appID/definitions", appWrite, handling.Wrap("权限定义创建失败", createAppPermissionHandler))
	group.PATCH("/:appID/definitions/:permID", appWrite, handling.Wrap("权限定义更新失败", updateAppPermissionHandler))
	group.DELETE("/:appID/definitions/:permID", appWrite, handling.Wrap("权限定义删除失败", deleteAppPermissionHandler))
	group.GET("/:appID/definitions/:permID/implies", appRead, handling.Wrap("权限继承获取失败", getAppPermissionImpliesHandler))
	group.PUT("/:appID/definitions/:permID/implies", appWrite, handling.Wrap("权限继承设置失败", setAppPermissionImpliesHandler))

	// 应用维度的用户组、成员与组权限
	group.GET("/:appID/groups/search/info", appRead, handling.Wrap("用户组搜索信息获取失败", appUserGroupSearchInfoHandler))
	group.POST("/:appID/groups/search/query", appRead, handling.Wrap("用户组搜索失败", appUserGroupSearchQueryHandler))
	group.POST("/:appID/groups", appWrite, handling.Wrap("用户组创建失败", createAppGroupHandler))
	group.GET("/:appID/groups/:groupID", appRead, handling.Wrap("用户组获取失败", getAppGroupHandler))
	group.PATCH("/:appID/groups/:groupID", appWrite, handling.Wrap("用户组更新失败", updateAppGroupHandler))
	group.DELETE("/:appID/groups/:groupID", appWrite, handling.Wrap("用户组删除失败", deleteAppGroupHandler))
	group.GET("/:appID/groups/:groupID/permissions", appRead, handling.Wrap("用户组权限获取失败", listAppGroupPermissionsHandler))
	group.PUT("/:appID/groups/:groupID/permissions", appWrite, handling.Wrap("用户组权限设置失败", setAppGroupPermissionsHandler))
	group.POST("/:appID/groups/:groupID/permissions", appWrite, handling.Wrap("用户组权限添加失败", addAppGroupPermissionsHandler))
	group.GET("/:appID/groups/:groupID/users", appRead, handling.Wrap("用户组成员列表获取失败", listAppGroupUsersHandler))
	group.POST("/:appID/groups/:groupID/users", appWrite, handling.Wrap("用户组成员授予失败", grantAppGroupUserHandler))
	group.DELETE("/:appID/groups/:groupID/users/:userID", appWrite, handling.Wrap("用户组成员撤销失败", revokeAppGroupUserHandler))

	// 应用维度的用户直接授权
	group.GET("/:appID/users/:userID/grants", appRead, handling.Wrap("应用用户授权列表获取失败", listAppUserGrantsHandler))
	group.POST("/:appID/users/:userID/grants", appWrite, handling.Wrap("应用用户授权失败", grantAppUserGrantHandler))
	group.DELETE("/:appID/users/:userID/grants", appWrite, handling.Wrap("应用用户授权撤销失败", revokeAppUserGrantHandler))
	group.GET("/:appID/users/:userID/effective", appRead, handling.Wrap("应用用户有效权限获取失败", getAppUserEffectivePermissionsHandler))

	// 全局维度的权限定义与用户组搜索
	group.GET("/definitions/search/info", globalRead, handling.Wrap("权限定义搜索信息获取失败", permissionSearchInfoHandler))
	group.POST("/definitions/search/query", globalRead, handling.Wrap("权限定义搜索失败", permissionSearchQueryHandler))
	group.GET("/groups/search/info", globalRead, handling.Wrap("用户组搜索信息获取失败", userGroupSearchInfoHandler))
	group.POST("/groups/search/query", globalRead, handling.Wrap("用户组搜索失败", userGroupSearchQueryHandler))

	// 权限目录重载
	group.GET("/reload/status", globalRead, handling.Wrap("权限重载状态获取失败", getReloadStatusHandler))
	group.POST("/reload", globalWrite, handling.Wrap("权限重载失败", reloadHandler))
}
