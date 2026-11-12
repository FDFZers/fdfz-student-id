package permissions

import (
	"fdfz-student-id/internal/service/perm"
	"net/http"
	"strings"

	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/service/userperm"
	"fdfz-student-id/internal/util/handling"

	"github.com/guregu/null/v6"

	"github.com/gin-gonic/gin"
)

// createAppPermissionRequestBody 是创建权限定义的请求体；Permission 为完整权限串（含命名空间）。
type createAppPermissionRequestBody struct {
	Permission  string `json:"permission"`
	Description string `json:"description"`
	Requestable bool   `json:"requestable"`
}

// createAppPermissionHandler 在指定应用下创建权限定义。
// 权限串必须解析合法且属于该应用的命名空间；成功后由重载器异步刷新权限目录。
func createAppPermissionHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)
	app, err := handling.ResolveApp(c)
	if err != nil {
		return err
	}

	var body createAppPermissionRequestBody
	if e := c.ShouldBindJSON(&body); e != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}

	// 解析并校验权限串（必须属于当前应用的命名空间）
	parsed, e := perm.ParsePermission(body.Permission)
	if e != nil {
		return errs.BadRequestError().AppendDetails("权限格式错误")
	}
	if parsed.Namespace != app.Namespace {
		return errs.BadRequestError().AppendDetails("权限命名空间不可用")
	}
	value := strings.Join(parsed.Nodes, ".")
	if err := handling.ValidatePermissionValue(value); err != nil {
		return err
	}
	if err := handling.ValidatePermissionDescription(body.Description); err != nil {
		return err
	}

	// 组装权限定义并写入数据库
	def := &model.PermissionDef{
		AppID:       app.ID,
		Value:       value,
		Description: body.Description,
		Requestable: body.Requestable,
		CreatedBy:   null.IntFrom(claims.UserID),
	}
	if err := userperm.CreatePermissionDef(c.Request.Context(), def); err != nil {
		return err
	}

	c.JSON(http.StatusOK, defJSON(def, app.Namespace))
	return nil
}

// updateAppPermissionRequestBody 是更新权限定义的请求体；字段为 nil 表示不修改，两者都为 nil 时报错。
type updateAppPermissionRequestBody struct {
	Description *string `json:"description"`
	Requestable *bool   `json:"requestable"`
}

// updateAppPermissionHandler 更新权限定义的描述与是否可申请；权限值与所属应用不可修改。
func updateAppPermissionHandler(c *gin.Context) *errs.Error {
	app, err := handling.ResolveApp(c)
	if err != nil {
		return err
	}
	permissionID, err := handling.ParseID(c, "permID", "权限定义")
	if err != nil {
		return err
	}

	var body updateAppPermissionRequestBody
	if e := c.ShouldBindJSON(&body); e != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}
	if body.Description == nil && body.Requestable == nil {
		return errs.BadRequestError().AppendDetails("没有需要更新的字段")
	}

	// 确认权限定义存在且属于该应用
	def, err := userperm.GetPermissionDefInApp(c.Request.Context(), app.ID, permissionID)
	if err != nil {
		return err
	}
	if def == nil {
		return errs.NotFoundError().AppendDetails("权限定义不存在")
	}

	// 合并请求中提供的字段，未提供的保持原值
	description := def.Description
	if body.Description != nil {
		description = *body.Description
	}
	requestable := def.Requestable
	if body.Requestable != nil {
		requestable = *body.Requestable
	}

	// 校验并写回数据库
	if err := handling.ValidatePermissionDescription(description); err != nil {
		return err
	}

	if err := userperm.UpdatePermissionDef(c.Request.Context(), permissionID, description, requestable); err != nil {
		return err
	}
	def.Description = description
	def.Requestable = requestable

	c.JSON(http.StatusOK, defJSON(def, app.Namespace))
	return nil
}

// deleteAppPermissionHandler 删除权限定义。
// 数据库会级联清理该定义的继承边与用户组关联；目录在异步重载后才更新。
func deleteAppPermissionHandler(c *gin.Context) *errs.Error {
	app, err := handling.ResolveApp(c)
	if err != nil {
		return err
	}
	permissionID, err := handling.ParseID(c, "permID", "权限定义")
	if err != nil {
		return err
	}

	def, err := userperm.GetPermissionDefInApp(c.Request.Context(), app.ID, permissionID)
	if err != nil {
		return err
	}
	if def == nil {
		return errs.NotFoundError().AppendDetails("权限定义不存在")
	}

	// 核心权限管理定义删除后无法再授予，会导致权限管理自锁。
	if app.ID == 1 && strings.HasPrefix(def.Value, "permissions.") {
		return errs.IllegalStateError().AppendDetails("核心权限定义不允许删除").Seal()
	}

	if err := userperm.DeletePermissionDef(c.Request.Context(), permissionID); err != nil {
		return err
	}

	c.JSON(http.StatusOK, gin.H{})
	return nil
}
