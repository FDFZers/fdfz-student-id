package permissions

import (
	"fdfz-student-id/internal/util/handling"
	"net/http"

	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/service/userperm"

	"github.com/gin-gonic/gin"
)

// buildImpliesResponse 构造权限继承信息响应：直接继承、传递继承以及反查（被哪些权限继承）。
func buildImpliesResponse(c *gin.Context, app *model.OAuthApp, def *model.PermissionDef) *errs.Error {
	ctx := c.Request.Context()

	direct, transitive, err := userperm.ListImplies(ctx, app.ID, def.ID)
	if err != nil {
		return err
	}
	impliedBy, err := userperm.ListImpliedBy(ctx, app.ID, def.ID)
	if err != nil {
		return err
	}

	c.JSON(http.StatusOK, gin.H{
		"permission":         defJSON(def, app.Namespace),
		"direct_implies":     defsJSON(direct, app.Namespace),
		"transitive_implies": defsJSON(transitive, app.Namespace),
		"implied_by":         defsJSON(impliedBy, app.Namespace),
	})
	return nil
}

// getAppPermissionImpliesHandler 返回指定权限定义的继承信息（直接、传递与被继承）。
func getAppPermissionImpliesHandler(c *gin.Context) *errs.Error {
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

	return buildImpliesResponse(c, app, def)
}

// setAppPermissionImpliesRequestBody 是设置直接继承关系的请求体；Implies 为完整权限串列表，语义为整体替换。
type setAppPermissionImpliesRequestBody struct {
	Implies []string `json:"implies"`
}

// setAppPermissionImpliesHandler 整体替换权限定义的直接继承关系。
// 注意：传入空数组会清空全部直接继承；循环依赖检测由服务层在事务内完成。
func setAppPermissionImpliesHandler(c *gin.Context) *errs.Error {
	app, err := handling.ResolveApp(c)
	if err != nil {
		return err
	}
	permissionID, err := handling.ParseID(c, "permID", "权限定义")
	if err != nil {
		return err
	}

	var body setAppPermissionImpliesRequestBody
	if e := c.ShouldBindJSON(&body); e != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}

	def, err := userperm.GetPermissionDefInApp(c.Request.Context(), app.ID, permissionID)
	if err != nil {
		return err
	}
	if def == nil {
		return errs.NotFoundError().AppendDetails("权限定义不存在")
	}

	defs, err := userperm.ResolvePermissionValues(c.Request.Context(), app.ID, app.Namespace, body.Implies)
	if err != nil {
		return err
	}
	impliedIDs := make([]int64, 0, len(defs))
	for _, implied := range defs {
		impliedIDs = append(impliedIDs, implied.ID)
	}

	if err := userperm.SetPermissionImplies(c.Request.Context(), app.ID, permissionID, impliedIDs); err != nil {
		return err
	}

	return buildImpliesResponse(c, app, def)
}
