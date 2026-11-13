package permissions

import (
	searchsvc "fdfz-student-id/internal/service/search"
	usersvc "fdfz-student-id/internal/service/user"
	"net/http"
	"time"

	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	userpermsvc "fdfz-student-id/internal/service/userperm"
	"fdfz-student-id/internal/util/handling"

	"github.com/guregu/null/v6"

	"github.com/gin-gonic/gin"
)

// respondGroupPermissions 查询并写出用户组直接拥有的权限定义列表（跨应用补充命名空间）。
func respondGroupPermissions(c *gin.Context, groupID int64) *errs.Error {
	defs, err := userpermsvc.ListRolePermissions(c.Request.Context(), groupID)
	if err != nil {
		return err
	}
	data, err := handling.DefsJSONMultiApp(c.Request.Context(), defs)
	if err != nil {
		return err
	}

	handling.RespondList(c, len(data), data)
	return nil
}

// createAppGroupRequestBody 是创建用户组的请求体。
type createAppGroupRequestBody struct {
	Name   string `json:"name"`
	Note   string `json:"note"`
	Public bool   `json:"public"`
}

// createAppGroupHandler 处理用户组创建：校验名称与备注后写入当前应用。
func createAppGroupHandler(c *gin.Context) *errs.Error {
	app, err := handling.ResolveApp(c)
	if err != nil {
		return err
	}

	var body createAppGroupRequestBody
	if err := handling.BindJSON(c, &body); err != nil {
		return err
	}
	if err := handling.ValidateUserGroupName(body.Name); err != nil {
		return err
	}
	if err := handling.ValidateUserGroupNote(body.Note); err != nil {
		return err
	}

	role := &model.Role{
		AppID:  app.ID,
		Name:   body.Name,
		Note:   body.Note,
		Public: body.Public,
	}
	if err := userpermsvc.CreateRole(c.Request.Context(), role); err != nil {
		return err
	}

	c.JSON(http.StatusOK, handling.GroupJSON(role))
	return nil
}

// getAppGroupHandler 处理用户组详情查询：本应用的组或其他应用的公开组均可见。
func getAppGroupHandler(c *gin.Context) *errs.Error {
	app, err := handling.ResolveApp(c)
	if err != nil {
		return err
	}
	groupID, err := handling.ParseID(c, "groupID", "用户组")
	if err != nil {
		return err
	}

	role, err := userpermsvc.GetRoleVisibleToApp(c.Request.Context(), app.ID, groupID)
	if err != nil {
		return err
	}
	if role == nil {
		return errs.NotFoundError().AppendDetails("用户组不存在")
	}

	c.JSON(http.StatusOK, handling.GroupJSON(role))
	return nil
}

// updateAppGroupRequestBody 是更新用户组的请求体，字段为 nil 表示不修改。
type updateAppGroupRequestBody struct {
	Name   *string `json:"name"`
	Note   *string `json:"note"`
	Public *bool   `json:"public"`
}

// updateAppGroupHandler 处理用户组更新：只能更新本应用的用户组，未提供的字段保持原值。
func updateAppGroupHandler(c *gin.Context) *errs.Error {
	app, err := handling.ResolveApp(c)
	if err != nil {
		return err
	}
	groupID, err := handling.ParseID(c, "groupID", "用户组")
	if err != nil {
		return err
	}

	var body updateAppGroupRequestBody
	if err := handling.BindJSON(c, &body); err != nil {
		return err
	}
	if body.Name == nil && body.Note == nil && body.Public == nil {
		return errs.BadRequestError().AppendDetails("没有需要更新的字段")
	}

	role, err := userpermsvc.GetRoleInApp(c.Request.Context(), app.ID, groupID)
	if err != nil {
		return err
	}
	if role == nil {
		return errs.NotFoundError().AppendDetails("用户组不存在")
	}

	// 未提供的字段沿用当前值。
	name := role.Name
	if body.Name != nil {
		name = *body.Name
	}
	note := role.Note
	if body.Note != nil {
		note = *body.Note
	}
	public := role.Public
	if body.Public != nil {
		public = *body.Public
	}

	if err := handling.ValidateUserGroupName(name); err != nil {
		return err
	}
	if err := handling.ValidateUserGroupNote(note); err != nil {
		return err
	}

	if err := userpermsvc.UpdateRole(c.Request.Context(), groupID, name, note, public); err != nil {
		return err
	}
	role.Name = name
	role.Note = note
	role.Public = public

	c.JSON(http.StatusOK, handling.GroupJSON(role))
	return nil
}

// deleteAppGroupHandler 处理用户组删除：只能删除本应用的用户组，组权限与成员级联清理。
func deleteAppGroupHandler(c *gin.Context) *errs.Error {
	app, err := handling.ResolveApp(c)
	if err != nil {
		return err
	}
	groupID, err := handling.ParseID(c, "groupID", "用户组")
	if err != nil {
		return err
	}

	role, err := userpermsvc.GetRoleInApp(c.Request.Context(), app.ID, groupID)
	if err != nil {
		return err
	}
	if role == nil {
		return errs.NotFoundError().AppendDetails("用户组不存在")
	}

	if err := userpermsvc.DeleteRole(c.Request.Context(), groupID); err != nil {
		return err
	}

	handling.RespondOK(c)
	return nil
}

// listAppGroupPermissionsHandler 处理组权限查询：本应用的组与其他应用的公开组均可见。
func listAppGroupPermissionsHandler(c *gin.Context) *errs.Error {
	app, err := handling.ResolveApp(c)
	if err != nil {
		return err
	}
	groupID, err := handling.ParseID(c, "groupID", "用户组")
	if err != nil {
		return err
	}

	role, err := userpermsvc.GetRoleVisibleToApp(c.Request.Context(), app.ID, groupID)
	if err != nil {
		return err
	}
	if role == nil {
		return errs.NotFoundError().AppendDetails("用户组不存在")
	}

	return respondGroupPermissions(c, groupID)
}

// setAppGroupPermissionsRequestBody 是整体替换组权限的请求体，权限为完整权限串。
type setAppGroupPermissionsRequestBody struct {
	Permissions []string `json:"permissions"`
}

// setAppGroupPermissionsHandler 处理组权限整体替换：只能修改本应用用户组，权限须属于当前应用。
func setAppGroupPermissionsHandler(c *gin.Context) *errs.Error {
	app, err := handling.ResolveApp(c)
	if err != nil {
		return err
	}
	groupID, err := handling.ParseID(c, "groupID", "用户组")
	if err != nil {
		return err
	}

	var body setAppGroupPermissionsRequestBody
	if err := handling.BindJSON(c, &body); err != nil {
		return err
	}

	role, err := userpermsvc.GetRoleInApp(c.Request.Context(), app.ID, groupID)
	if err != nil {
		return err
	}
	if role == nil {
		return errs.NotFoundError().AppendDetails("用户组不存在")
	}

	defs, err := userpermsvc.ResolvePermissionValues(c.Request.Context(), app.ID, app.Namespace, body.Permissions)
	if err != nil {
		return err
	}
	permissionIDs := make([]int64, 0, len(defs))
	for _, def := range defs {
		permissionIDs = append(permissionIDs, def.ID)
	}

	if err := userpermsvc.SetRolePermissions(c.Request.Context(), db.R, app.ID, groupID, permissionIDs); err != nil {
		return err
	}

	return respondGroupPermissions(c, groupID)
}

// addAppGroupPermissionsRequestBody 是追加组权限的请求体，权限为完整权限串。
type addAppGroupPermissionsRequestBody struct {
	Permissions []string `json:"permissions"`
}

// addAppGroupPermissionsHandler 处理组权限追加：空权限列表直接成功，重复权限由服务层去重。
// 写操作仅限本应用的用户组，防止越权修改其他应用的组权限。
func addAppGroupPermissionsHandler(c *gin.Context) *errs.Error {
	app, err := handling.ResolveApp(c)
	if err != nil {
		return err
	}
	groupID, err := handling.ParseID(c, "groupID", "用户组")
	if err != nil {
		return err
	}

	var body addAppGroupPermissionsRequestBody
	if err := handling.BindJSON(c, &body); err != nil {
		return err
	}

	role, err := userpermsvc.GetRoleInApp(c.Request.Context(), app.ID, groupID)
	if err != nil {
		return err
	}
	if role == nil {
		return errs.NotFoundError().AppendDetails("用户组不存在")
	}

	defs, err := userpermsvc.ResolvePermissionValues(c.Request.Context(), app.ID, app.Namespace, body.Permissions)
	if err != nil {
		return err
	}
	permissionIDs := make([]int64, 0, len(defs))
	for _, def := range defs {
		permissionIDs = append(permissionIDs, def.ID)
	}

	if err := userpermsvc.AddRolePermissions(c.Request.Context(), groupID, permissionIDs); err != nil {
		return err
	}

	return respondGroupPermissions(c, groupID)
}

// listAppGroupUsersHandler 处理用户组成员列表查询：本应用的组与其他应用的公开组均可见。
func listAppGroupUsersHandler(c *gin.Context) *errs.Error {
	app, err := handling.ResolveApp(c)
	if err != nil {
		return err
	}
	groupID, err := handling.ParseID(c, "groupID", "用户组")
	if err != nil {
		return err
	}

	role, err := userpermsvc.GetRoleVisibleToApp(c.Request.Context(), app.ID, groupID)
	if err != nil {
		return err
	}
	if role == nil {
		return errs.NotFoundError().AppendDetails("用户组不存在")
	}

	limit, offset := searchsvc.ParseQueryPagination(c)

	users, count, err := userpermsvc.ListRoleUsers(c.Request.Context(), groupID, limit, offset)
	if err != nil {
		return err
	}

	handling.RespondList(c, count, handling.GroupUsersJSON(users))
	return nil
}

// grantAppGroupUserRequestBody 是授予用户组的请求体，有效期为可选的时间区间。
type grantAppGroupUserRequestBody struct {
	UserID     int64      `json:"user_id"`
	ValidFrom  *time.Time `json:"valid_from"`
	ValidUntil *time.Time `json:"valid_until"`
}

// grantAppGroupUserHandler 处理用户组授予：只能向本应用的用户组添加成员，授予人为当前操作者。
func grantAppGroupUserHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)
	app, err := handling.ResolveApp(c)
	if err != nil {
		return err
	}
	groupID, err := handling.ParseID(c, "groupID", "用户组")
	if err != nil {
		return err
	}

	// 解析请求体并校验用户 ID 与有效期区间。
	var body grantAppGroupUserRequestBody
	if err := handling.BindJSON(c, &body); err != nil {
		return err
	}
	if err := handling.ValidateUserID(body.UserID); err != nil {
		return err
	}
	if err := handling.ValidateValidRange(body.ValidFrom, body.ValidUntil); err != nil {
		return err
	}

	// 校验用户组与目标用户均存在。
	role, err := userpermsvc.GetRoleInApp(c.Request.Context(), app.ID, groupID)
	if err != nil {
		return err
	}
	if role == nil {
		return errs.NotFoundError().AppendDetails("用户组不存在")
	}

	usr, err := usersvc.GetUserByID(c.Request.Context(), body.UserID)
	if err != nil {
		return err
	} else if usr == nil {
		return errs.NotFoundError().AppendDetails("用户不存在")
	}

	// 写入成员关系并回显成员信息。
	grant := &model.UserRole{
		UserID:     body.UserID,
		RoleID:     groupID,
		GrantedBy:  null.IntFrom(claims.UserID),
		ValidFrom:  null.TimeFromPtr(body.ValidFrom),
		ValidUntil: null.TimeFromPtr(body.ValidUntil),
	}
	if err := userpermsvc.GrantUserRole(c.Request.Context(), grant); err != nil {
		return err
	}

	member := &userpermsvc.RoleUser{
		UserID:     usr.ID,
		Username:   usr.Username,
		Nickname:   usr.Nickname,
		Deleted:    usr.DeletedAt.Valid,
		GrantedBy:  grant.GrantedBy,
		ValidFrom:  grant.ValidFrom,
		ValidUntil: grant.ValidUntil,
		CreatedAt:  time.Now(),
	}

	c.JSON(http.StatusOK, gin.H{
		"data": handling.GroupUserJSON(member),
	})
	return nil
}

// revokeAppGroupUserHandler 处理用户组成员撤销：只能撤销本应用用户组的成员关系，重复撤销幂等成功。
func revokeAppGroupUserHandler(c *gin.Context) *errs.Error {
	app, err := handling.ResolveApp(c)
	if err != nil {
		return err
	}
	groupID, err := handling.ParseID(c, "groupID", "用户组")
	if err != nil {
		return err
	}
	userID, err := handling.ParseID(c, "userID", "用户")
	if err != nil {
		return err
	}

	role, err := userpermsvc.GetRoleInApp(c.Request.Context(), app.ID, groupID)
	if err != nil {
		return err
	}
	if role == nil {
		return errs.NotFoundError().AppendDetails("用户组不存在")
	}

	if err := userpermsvc.RevokeUserRole(c.Request.Context(), userID, groupID); err != nil {
		return err
	}

	handling.RespondOK(c)
	return nil
}
