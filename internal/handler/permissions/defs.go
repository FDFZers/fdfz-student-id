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

type createAppPermissionRequestBody struct {
	Permission  string `json:"permission"`
	Description string `json:"description"`
	Requestable bool   `json:"requestable"`
}

func createAppPermissionHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)
	app, err := handling.ResolveApp(c)
	if err != nil {
		return err
	}

	var body createAppPermissionRequestBody
	if bindErr := c.ShouldBindJSON(&body); bindErr != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}

	parsed, e := perm.ParsePermission(body.Permission)
	if e != nil {
		return errs.BadRequestError().AppendDetails("权限格式错误", "创建权限定义失败")
	}
	if parsed.Namespace != app.Namespace {
		return errs.BadRequestError().AppendDetails("权限命名空间不可用", "创建权限定义失败")
	}
	value := strings.Join(parsed.Nodes, ".")
	if err := handling.ValidatePermissionValue(value); err != nil {
		return err.AppendDetails("创建权限定义失败")
	}
	if err := handling.ValidatePermissionDescription(body.Description); err != nil {
		return err.AppendDetails("创建权限定义失败")
	}

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

type updateAppPermissionRequestBody struct {
	Description *string `json:"description"`
	Requestable *bool   `json:"requestable"`
}

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
	if bindErr := c.ShouldBindJSON(&body); bindErr != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}
	if body.Description == nil && body.Requestable == nil {
		return errs.BadRequestError().AppendDetails("没有需要更新的字段")
	}

	def, err := userperm.GetPermissionDefInApp(c.Request.Context(), app.ID, permissionID)
	if err != nil {
		return err
	}
	if def == nil {
		return errs.NotFoundError().AppendDetails("权限定义不存在")
	}

	description := def.Description
	if body.Description != nil {
		description = *body.Description
	}
	requestable := def.Requestable
	if body.Requestable != nil {
		requestable = *body.Requestable
	}

	if err := handling.ValidatePermissionDescription(description); err != nil {
		return err.AppendDetails("更新权限定义失败")
	}

	if err := userperm.UpdatePermissionDef(c.Request.Context(), permissionID, description, requestable); err != nil {
		return err
	}
	def.Description = description
	def.Requestable = requestable

	c.JSON(http.StatusOK, defJSON(def, app.Namespace))
	return nil
}

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

	if err := userperm.DeletePermissionDef(c.Request.Context(), permissionID); err != nil {
		return err
	}

	c.JSON(http.StatusOK, gin.H{})
	return nil
}
