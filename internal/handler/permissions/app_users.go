package permissions

import (
	searchsvc "fdfz-student-id/internal/service/search"
	"net/http"
	"strings"
	"time"

	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	userpermsvc "fdfz-student-id/internal/service/userperm"
	"fdfz-student-id/internal/util/handling"

	"github.com/gin-gonic/gin"
	"github.com/guregu/null/v6"
)

// listAppUserGrantsHandler 处理应用维度直接授权列表查询：只返回本应用授予该用户的权限。
func listAppUserGrantsHandler(c *gin.Context) *errs.Error {
	app, err := handling.ResolveApp(c)
	if err != nil {
		return err
	}
	userID, err := handling.ParseID(c, "userID", "用户")
	if err != nil {
		return err
	}
	if err := handling.EnsureUserExists(c, userID); err != nil {
		return err
	}
	limit, offset := searchsvc.ParseQueryPagination(c)

	grants, count, err := userpermsvc.ListUserPermissionGrantsInApp(c.Request.Context(), userID, app.ID, limit, offset)
	if err != nil {
		return err
	}

	handling.RespondList(c, count, handling.GrantsJSON(grants))
	return nil
}

// grantAppUserGrantRequestBody 是应用直接授权用户的请求体，有效期为可选的时间区间。
type grantAppUserGrantRequestBody struct {
	Permission string     `json:"permission"`
	ValidFrom  *time.Time `json:"valid_from"`
	ValidUntil *time.Time `json:"valid_until"`
	Note       string     `json:"note"`
}

// grantAppUserGrantHandler 处理应用直接授权：权限必须是当前应用的权限定义，授予来源记为当前应用。
func grantAppUserGrantHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)
	app, err := handling.ResolveApp(c)
	if err != nil {
		return err
	}
	userID, err := handling.ParseID(c, "userID", "用户")
	if err != nil {
		return err
	}

	// 解析请求体并校验权限名、备注与有效期区间。
	var body grantAppUserGrantRequestBody
	if err := handling.BindJSON(c, &body); err != nil {
		return err
	}
	if err := handling.ValidateGrantPermission(body.Permission); err != nil {
		return err
	}
	if err := handling.ValidateGrantNote(body.Note); err != nil {
		return err
	}
	if err := handling.ValidateValidRange(body.ValidFrom, body.ValidUntil); err != nil {
		return err
	}

	// 权限必须属于该应用（同时完成归属校验）。
	defs, err := userpermsvc.ResolvePermissionValues(c.Request.Context(), app.ID, app.Namespace, []string{body.Permission})
	if err != nil {
		return err
	}
	if len(defs) == 0 {
		return errs.NotFoundError().AppendDetails("权限定义不存在")
	}
	if err := handling.EnsureUserExists(c, userID); err != nil {
		return err
	}

	grant := &model.UserPermissionGrant{
		UserID:          userID,
		Permission:      body.Permission,
		GrantedByUserID: null.IntFrom(claims.UserID),
		GrantedByAppID:  app.ID,
		ValidFrom:       null.TimeFromPtr(body.ValidFrom),
		ValidUntil:      null.TimeFromPtr(body.ValidUntil),
		Note:            body.Note,
	}
	if err := userpermsvc.GrantUserPermission(c.Request.Context(), grant); err != nil {
		return err
	}

	c.JSON(http.StatusOK, handling.GrantJSON(grant))
	return nil
}

// revokeAppUserGrantHandler 处理应用直接授权撤销：权限由查询参数传入，只能撤销本应用授予的授权。
func revokeAppUserGrantHandler(c *gin.Context) *errs.Error {
	app, err := handling.ResolveApp(c)
	if err != nil {
		return err
	}
	userID, err := handling.ParseID(c, "userID", "用户")
	if err != nil {
		return err
	}

	permStr := c.Query("permission")
	if err := handling.ValidateAppPermissionPattern(permStr, app.Namespace); err != nil {
		return err
	}

	existing, err := userpermsvc.GetUserPermissionGrant(c.Request.Context(), userID, permStr)
	if err != nil {
		return err
	}
	if existing == nil || existing.GrantedByAppID != app.ID {
		return errs.NotFoundError().AppendDetails("用户授权不存在")
	}

	if err := userpermsvc.RevokeUserPermission(c.Request.Context(), userID, permStr); err != nil {
		return err
	}

	handling.RespondOK(c)
	return nil
}

// getAppUserEffectivePermissionsHandler 处理应用维度有效权限查询：只返回当前应用命名空间下的权限。
func getAppUserEffectivePermissionsHandler(c *gin.Context) *errs.Error {
	app, err := handling.ResolveApp(c)
	if err != nil {
		return err
	}
	userID, err := handling.ParseID(c, "userID", "用户")
	if err != nil {
		return err
	}
	if err := handling.EnsureUserExists(c, userID); err != nil {
		return err
	}

	permissions, err := userpermsvc.ListUserEffectivePermissions(c.Request.Context(), userID)
	if err != nil {
		return err
	}

	prefix := app.Namespace + ":"
	filtered := make([]string, 0, len(permissions))
	for _, permission := range permissions {
		if strings.HasPrefix(permission, prefix) {
			filtered = append(filtered, permission)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"count":       len(filtered),
		"permissions": filtered,
	})
	return nil
}
