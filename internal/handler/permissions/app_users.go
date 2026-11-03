package permissions

import (
	"fdfz-student-id/internal/service/perm"
	"fdfz-student-id/internal/service/search"
	"net/http"
	"strings"
	"time"

	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/service/userperm"
	"fdfz-student-id/internal/util/handling"

	"github.com/gin-gonic/gin"
	"github.com/guregu/null/v6"
)

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
	limit, offset := search.ParseQueryPagination(c)

	grants, count, err := userperm.ListUserPermissionGrantsInApp(c.Request.Context(), userID, app.ID, limit, offset)
	if err != nil {
		return err
	}

	c.JSON(http.StatusOK, gin.H{
		"count": count,
		"data":  grantsJSON(grants),
	})
	return nil
}

type grantAppUserGrantRequestBody struct {
	Permission string     `json:"permission"`
	ValidFrom  *time.Time `json:"valid_from"`
	ValidUntil *time.Time `json:"valid_until"`
	Note       string     `json:"note"`
}

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

	var body grantAppUserGrantRequestBody
	if bindErr := c.ShouldBindJSON(&body); bindErr != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}
	if err := handling.ValidateGrantPermission(body.Permission); err != nil {
		return err.AppendDetails("应用用户授权失败")
	}
	if err := handling.ValidateGrantNote(body.Note); err != nil {
		return err.AppendDetails("应用用户授权失败")
	}
	if err := handling.ValidateValidRange(body.ValidFrom, body.ValidUntil); err != nil {
		return err.AppendDetails("应用用户授权失败")
	}

	// 权限必须属于该应用（同时完成归属校验）。
	defs, err := userperm.ResolvePermissionValues(c.Request.Context(), app.ID, app.Namespace, []string{body.Permission})
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
	if err := userperm.GrantUserPermission(c.Request.Context(), grant); err != nil {
		return err
	}

	c.JSON(http.StatusOK, grantJSON(grant))
	return nil
}

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
	if permStr == "" {
		return errs.BadRequestError().AppendDetails("未提供权限")
	}

	if parsed, err := perm.ParsePattern(permStr); err != nil {
		return errs.BadRequestError().AppendDetails("权限格式错误")
	} else if parsed.Namespace != app.Namespace {
		return errs.BadRequestError().AppendDetails("权限命名空间错误")
	}

	existing, err := userperm.GetUserPermissionGrant(c.Request.Context(), userID, permStr)
	if err != nil {
		return err
	}
	if existing == nil || existing.GrantedByAppID != app.ID {
		return errs.NotFoundError().AppendDetails("用户授权不存在")
	}

	if err := userperm.RevokeUserPermission(c.Request.Context(), userID, permStr); err != nil {
		return err
	}

	c.JSON(http.StatusOK, gin.H{})
	return nil
}

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

	permissions, err := userperm.ListUserEffectivePermissions(c.Request.Context(), userID)
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
