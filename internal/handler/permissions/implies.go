package permissions

import (
	"fdfz-student-id/internal/util/handling"
	"net/http"
	"time"

	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	userpermsvc "fdfz-student-id/internal/service/userperm"

	"github.com/gin-gonic/gin"
	"github.com/guregu/null/v6"
)

// buildImpliesResponse 构造权限继承信息响应：直接继承、传递继承以及反查（被哪些权限继承）。
func buildImpliesResponse(c *gin.Context, app *model.OAuthApp, def *model.PermissionDef) *errs.Error {
	ctx := c.Request.Context()

	direct, transitive, err := userpermsvc.ListImplies(ctx, app.ID, def.ID)
	if err != nil {
		return err
	}
	impliedBy, err := userpermsvc.ListImpliedBy(ctx, app.ID, def.ID)
	if err != nil {
		return err
	}

	c.JSON(http.StatusOK, gin.H{
		"permission":         handling.DefJSON(def, app.Namespace),
		"direct_implies":     handling.ImplicationsJSON(direct, app.Namespace),
		"transitive_implies": handling.DefsJSON(transitive, app.Namespace),
		"implied_by":         handling.ImplicationsJSON(impliedBy, app.Namespace),
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

	def, err := userpermsvc.GetPermissionDefInApp(c.Request.Context(), app.ID, permissionID)
	if err != nil {
		return err
	}
	if def == nil {
		return errs.NotFoundError().AppendDetails("权限定义不存在")
	}

	return buildImpliesResponse(c, app, def)
}

type permissionImplyRequest struct {
	Permission string     `json:"permission"`
	ValidFrom  *time.Time `json:"valid_from"`
	ValidUntil *time.Time `json:"valid_until"`
	Note       string     `json:"note"`
}

type setAppPermissionImpliesRequestBody struct {
	Implies []permissionImplyRequest `json:"implies"`
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
	if err := handling.BindJSON(c, &body); err != nil {
		return err
	}

	def, err := userpermsvc.GetPermissionDefInApp(c.Request.Context(), app.ID, permissionID)
	if err != nil {
		return err
	}
	if def == nil {
		return errs.NotFoundError().AppendDetails("权限定义不存在")
	}

	values := make([]string, 0, len(body.Implies))
	for _, item := range body.Implies {
		values = append(values, item.Permission)
	}
	defs, err := userpermsvc.ResolvePermissionValues(c.Request.Context(), app.ID, app.Namespace, values)
	if err != nil {
		return err
	}

	claims := handling.MustGetClaims(c)
	implications := make([]*model.PermissionImply, 0, len(defs))
	for i, implied := range defs {
		implications = append(implications, &model.PermissionImply{
			PermissionID:        permissionID,
			ImpliedPermissionID: implied.ID,
			GrantedByUserID:     null.IntFrom(claims.UserID),
			ValidFrom:           null.TimeFromPtr(body.Implies[i].ValidFrom),
			ValidUntil:          null.TimeFromPtr(body.Implies[i].ValidUntil),
			Note:                body.Implies[i].Note,
		})
	}

	if err := userpermsvc.SetPermissionImplies(
		c.Request.Context(), db.R, app.ID, permissionID, implications,
	); err != nil {
		return err
	}

	return buildImpliesResponse(c, app, def)
}
