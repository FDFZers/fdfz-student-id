package permissions

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/middleware"
	"fdfz-student-id/internal/model"
	appsvc "fdfz-student-id/internal/service/app"
	"fdfz-student-id/internal/service/perm"
	"fdfz-student-id/internal/service/userperm"
	"fdfz-student-id/internal/util/handling"

	"github.com/gin-gonic/gin"
)

// InitRoutes 在 /permissions 下注册权限管理相关路由。
// 应用维度接口用 RequireAppAccess 鉴权：拥有全局权限，或拥有 owned_apps 系列权限且是该应用所有者；
// 全局维度接口用 RequirePermission 鉴权。
func InitRoutes(internal *gin.RouterGroup) {
	group := internal.Group("/permissions")

	appRead := middleware.RequireAppAccess("appID", perm.PermPermissionsRead, perm.PermPermissionRead)
	appWrite := middleware.RequireAppAccess("appID", perm.PermPermissionsWrite, perm.PermPermissionWrite)
	globalRead := middleware.RequirePermission(perm.PermPermissionsRead)
	globalWrite := middleware.RequirePermission(perm.PermPermissionsWrite)

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

// defJSON 把权限定义渲染为 API 响应。PermissionDef 本身只有 AppID，命名空间需由调用方按应用提供。
func defJSON(def *model.PermissionDef, namespace string) gin.H {
	return gin.H{
		"id":          def.ID,
		"app_id":      def.AppID,
		"namespace":   namespace,
		"permission":  perm.Render(namespace, def.Value),
		"value":       def.Value,
		"description": def.Description,
		"requestable": def.Requestable,
		"created_by":  def.CreatedBy,
		"created_at":  def.CreatedAt,
		"updated_at":  def.UpdatedAt,
	}
}

// defsJSON 把同一应用内的多个权限定义渲染为数组。
func defsJSON(defs []*model.PermissionDef, namespace string) []gin.H {
	data := make([]gin.H, 0, len(defs))
	for _, def := range defs {
		data = append(data, defJSON(def, namespace))
	}
	return data
}

// defsJSONMultiApp 为跨应用查询批量补全命名空间；会查询全部未删除应用，仅适合管理端小批量结果。
func defsJSONMultiApp(c *gin.Context, defs []*model.PermissionDef) ([]gin.H, *errs.Error) {
	apps, err := appsvc.ListAllApps(c.Request.Context())
	if err != nil {
		return nil, err
	}
	namespaces := make(map[int64]string, len(apps))
	for _, app := range apps {
		namespaces[app.ID] = app.Namespace
	}

	data := make([]gin.H, 0, len(defs))
	for _, def := range defs {
		data = append(data, defJSON(def, namespaces[def.AppID]))
	}
	return data, nil
}

// groupJSON 把用户组（Role）渲染为 API 响应。
func groupJSON(role *model.Role) gin.H {
	return gin.H{
		"id":         role.ID,
		"app_id":     role.AppID,
		"name":       role.Name,
		"note":       role.Note,
		"public":     role.Public,
		"created_at": role.CreatedAt,
		"updated_at": role.UpdatedAt,
	}
}

// groupUserJSON 把用户组成员渲染为 API 响应。
func groupUserJSON(user *userperm.RoleUser) gin.H {
	return gin.H{
		"user_id":     user.UserID,
		"username":    user.Username,
		"nickname":    user.Nickname,
		"deleted":     user.Deleted,
		"granted_by":  user.GrantedBy,
		"valid_from":  user.ValidFrom,
		"valid_until": user.ValidUntil,
		"created_at":  user.CreatedAt,
	}
}

// groupUsersJSON 把用户组成员列表渲染为数组。
func groupUsersJSON(users []*userperm.RoleUser) []gin.H {
	data := make([]gin.H, 0, len(users))
	for _, user := range users {
		data = append(data, groupUserJSON(user))
	}
	return data
}

// grantJSON 把用户直接授权记录渲染为 API 响应。
func grantJSON(grant *model.UserPermissionGrant) gin.H {
	return gin.H{
		"id":                 grant.ID,
		"user_id":            grant.UserID,
		"permission":         grant.Permission,
		"granted_by_user_id": grant.GrantedByUserID,
		"granted_by_app_id":  grant.GrantedByAppID,
		"valid_from":         grant.ValidFrom,
		"valid_until":        grant.ValidUntil,
		"note":               grant.Note,
		"created_at":         grant.CreatedAt,
		"updated_at":         grant.UpdatedAt,
	}
}

// grantsJSON 把用户直接授权列表渲染为数组。
func grantsJSON(grants []*model.UserPermissionGrant) []gin.H {
	data := make([]gin.H, 0, len(grants))
	for _, grant := range grants {
		data = append(data, grantJSON(grant))
	}
	return data
}
