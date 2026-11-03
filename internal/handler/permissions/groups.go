package permissions

import (
	"fdfz-student-id/internal/service/search"
	"fdfz-student-id/internal/service/user"
	"net/http"
	"time"

	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/service/userperm"
	"fdfz-student-id/internal/util/handling"

	"github.com/guregu/null/v6"

	"github.com/gin-gonic/gin"
)

func respondGroupPermissions(c *gin.Context, groupID int64) *errs.Error {
	defs, err := userperm.ListRolePermissions(c.Request.Context(), groupID)
	if err != nil {
		return err
	}
	data, err := defsJSONMultiApp(c, defs)
	if err != nil {
		return err
	}

	c.JSON(http.StatusOK, gin.H{
		"count": len(data),
		"data":  data,
	})
	return nil
}

type createAppGroupRequestBody struct {
	Name   string `json:"name"`
	Note   string `json:"note"`
	Public bool   `json:"public"`
}

func createAppGroupHandler(c *gin.Context) *errs.Error {
	app, err := handling.ResolveApp(c)
	if err != nil {
		return err
	}

	var body createAppGroupRequestBody
	if bindErr := c.ShouldBindJSON(&body); bindErr != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}
	if err := handling.ValidateUserGroupName(body.Name); err != nil {
		return err.AppendDetails("创建用户组失败")
	}
	if err := handling.ValidateUserGroupNote(body.Note); err != nil {
		return err.AppendDetails("创建用户组失败")
	}

	role := &model.Role{
		AppID:  app.ID,
		Name:   body.Name,
		Note:   body.Note,
		Public: body.Public,
	}
	if err := userperm.CreateRole(c.Request.Context(), role); err != nil {
		return err
	}

	c.JSON(http.StatusOK, groupJSON(role))
	return nil
}

func getAppGroupHandler(c *gin.Context) *errs.Error {
	app, err := handling.ResolveApp(c)
	if err != nil {
		return err
	}
	groupID, err := handling.ParseID(c, "groupID", "用户组")
	if err != nil {
		return err
	}

	role, err := userperm.GetRoleVisibleToApp(c.Request.Context(), app.ID, groupID)
	if err != nil {
		return err
	}
	if role == nil {
		return errs.NotFoundError().AppendDetails("用户组不存在")
	}

	c.JSON(http.StatusOK, groupJSON(role))
	return nil
}

type updateAppGroupRequestBody struct {
	Name   *string `json:"name"`
	Note   *string `json:"note"`
	Public *bool   `json:"public"`
}

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
	if bindErr := c.ShouldBindJSON(&body); bindErr != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}
	if body.Name == nil && body.Note == nil && body.Public == nil {
		return errs.BadRequestError().AppendDetails("没有需要更新的字段")
	}

	role, err := userperm.GetRoleInApp(c.Request.Context(), app.ID, groupID)
	if err != nil {
		return err
	}
	if role == nil {
		return errs.NotFoundError().AppendDetails("用户组不存在")
	}

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
		return err.AppendDetails("更新用户组失败")
	}
	if err := handling.ValidateUserGroupNote(note); err != nil {
		return err.AppendDetails("更新用户组失败")
	}

	if err := userperm.UpdateRole(c.Request.Context(), groupID, name, note, public); err != nil {
		return err
	}
	role.Name = name
	role.Note = note
	role.Public = public

	c.JSON(http.StatusOK, groupJSON(role))
	return nil
}

func deleteAppGroupHandler(c *gin.Context) *errs.Error {
	app, err := handling.ResolveApp(c)
	if err != nil {
		return err
	}
	groupID, err := handling.ParseID(c, "groupID", "用户组")
	if err != nil {
		return err
	}

	role, err := userperm.GetRoleInApp(c.Request.Context(), app.ID, groupID)
	if err != nil {
		return err
	}
	if role == nil {
		return errs.NotFoundError().AppendDetails("用户组不存在")
	}

	if err := userperm.DeleteRole(c.Request.Context(), groupID); err != nil {
		return err
	}

	c.JSON(http.StatusOK, gin.H{})
	return nil
}

func listAppGroupPermissionsHandler(c *gin.Context) *errs.Error {
	app, err := handling.ResolveApp(c)
	if err != nil {
		return err
	}
	groupID, err := handling.ParseID(c, "groupID", "用户组")
	if err != nil {
		return err
	}

	role, err := userperm.GetRoleVisibleToApp(c.Request.Context(), app.ID, groupID)
	if err != nil {
		return err
	}
	if role == nil {
		return errs.NotFoundError().AppendDetails("用户组不存在")
	}

	return respondGroupPermissions(c, groupID)
}

type setAppGroupPermissionsRequestBody struct {
	Permissions []string `json:"permissions"`
}

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
	if bindErr := c.ShouldBindJSON(&body); bindErr != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}

	role, err := userperm.GetRoleInApp(c.Request.Context(), app.ID, groupID)
	if err != nil {
		return err
	}
	if role == nil {
		return errs.NotFoundError().AppendDetails("用户组不存在")
	}

	defs, err := userperm.ResolvePermissionValues(c.Request.Context(), app.ID, app.Namespace, body.Permissions)
	if err != nil {
		return err
	}
	permissionIDs := make([]int64, 0, len(defs))
	for _, def := range defs {
		permissionIDs = append(permissionIDs, def.ID)
	}

	if err := userperm.SetRolePermissions(c.Request.Context(), app.ID, groupID, permissionIDs); err != nil {
		return err
	}

	return respondGroupPermissions(c, groupID)
}

type addAppGroupPermissionsRequestBody struct {
	Permissions []string `json:"permissions"`
}

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
	if bindErr := c.ShouldBindJSON(&body); bindErr != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}

	role, err := userperm.GetRoleVisibleToApp(c.Request.Context(), app.ID, groupID)
	if err != nil {
		return err
	}
	if role == nil {
		return errs.NotFoundError().AppendDetails("用户组不存在")
	}
	if role.AppID != app.ID && !role.Public {
		// 防御性校验：GetRoleVisibleToApp 已保证不可见即 nil。
		return errs.NotFoundError().AppendDetails("用户组不存在")
	}

	defs, err := userperm.ResolvePermissionValues(c.Request.Context(), app.ID, app.Namespace, body.Permissions)
	if err != nil {
		return err
	}
	permissionIDs := make([]int64, 0, len(defs))
	for _, def := range defs {
		permissionIDs = append(permissionIDs, def.ID)
	}

	if err := userperm.AddRolePermissions(c.Request.Context(), groupID, permissionIDs); err != nil {
		return err
	}

	return respondGroupPermissions(c, groupID)
}

func listAppGroupUsersHandler(c *gin.Context) *errs.Error {
	app, err := handling.ResolveApp(c)
	if err != nil {
		return err
	}
	groupID, err := handling.ParseID(c, "groupID", "用户组")
	if err != nil {
		return err
	}

	role, err := userperm.GetRoleVisibleToApp(c.Request.Context(), app.ID, groupID)
	if err != nil {
		return err
	}
	if role == nil {
		return errs.NotFoundError().AppendDetails("用户组不存在")
	}

	limit, offset := search.ParseQueryPagination(c)

	users, count, err := userperm.ListRoleUsers(c.Request.Context(), groupID, limit, offset)
	if err != nil {
		return err
	}

	c.JSON(http.StatusOK, gin.H{
		"count": count,
		"data":  groupUsersJSON(users),
	})
	return nil
}

type grantAppGroupUserRequestBody struct {
	UserID     int64      `json:"user_id"`
	ValidFrom  *time.Time `json:"valid_from"`
	ValidUntil *time.Time `json:"valid_until"`
}

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

	var body grantAppGroupUserRequestBody
	if bindErr := c.ShouldBindJSON(&body); bindErr != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}
	if body.UserID <= 0 {
		return errs.BadRequestError().AppendDetails("无效的用户 ID")
	}
	if err := handling.ValidateValidRange(body.ValidFrom, body.ValidUntil); err != nil {
		return err.AppendDetails("用户组成员授予失败")
	}

	role, err := userperm.GetRoleInApp(c.Request.Context(), app.ID, groupID)
	if err != nil {
		return err
	}
	if role == nil {
		return errs.NotFoundError().AppendDetails("用户组不存在")
	}

	usr, err := user.GetUserByID(c, body.UserID)
	if err != nil {
		return err
	} else if usr == nil {
		return errs.NotFoundError().AppendDetails("用户不存在")
	}

	grant := &model.UserRole{
		UserID:     body.UserID,
		RoleID:     groupID,
		GrantedBy:  null.IntFrom(claims.UserID),
		ValidFrom:  null.TimeFromPtr(body.ValidFrom),
		ValidUntil: null.TimeFromPtr(body.ValidUntil),
	}
	if err := userperm.GrantUserRole(c.Request.Context(), grant); err != nil {
		return err
	}

	member := &userperm.RoleUser{
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
		"data": groupUserJSON(member),
	})
	return nil
}

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

	role, err := userperm.GetRoleInApp(c.Request.Context(), app.ID, groupID)
	if err != nil {
		return err
	}
	if role == nil {
		return errs.NotFoundError().AppendDetails("用户组不存在")
	}

	if err := userperm.RevokeUserRole(c.Request.Context(), userID, groupID); err != nil {
		return err
	}

	c.JSON(http.StatusOK, gin.H{})
	return nil
}
