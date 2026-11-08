package permissions

import (
	"fdfz-student-id/internal/util/handling"
	"net/http"
	"time"

	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/service/perm"
	"fdfz-student-id/internal/service/search"

	sq "github.com/Masterminds/squirrel"
	"github.com/gin-gonic/gin"
	"github.com/guregu/null/v6"
)

// permissionSearchCfg 是权限定义的搜索配置：可查询字段、排序字段、标签与默认排序。
// 表别名 pd/a 需与各 handler 追加的 where 条件保持一致。
var permissionSearchCfg = search.SearchConfig{
	Table: "permission_defs pd JOIN oauth_apps a ON a.id = pd.app_id",
	Item:  "权限定义",
	Columns: []string{
		"pd.id", "pd.app_id", "a.namespace", "pd.value", "pd.description",
		"pd.requestable", "pd.created_by", "pd.created_at", "pd.updated_at",
	},
	Fields: []search.Field{
		{ID: "id", Column: "pd.id", Numeric: true},
		{ID: "app_id", Column: "pd.app_id", Numeric: true},
		{ID: "namespace", Column: "a.namespace"},
		{ID: "value", Column: "pd.value"},
		{ID: "description", Column: "pd.description"},
	},
	MatchMethods: search.MatchMethodValues(),
	SortableFields: []search.Field{
		{ID: "id", Column: "pd.id"},
		{ID: "value", Column: "pd.value"},
		{ID: "created_at", Column: "pd.created_at"},
	},
	Tags: []search.Tag{
		{ID: "requestable", Column: "pd.requestable", ValueMap: search.ValueMapOf([]string{"true", "false"})},
	},
	DefaultSortColumn: "pd.id",
}

// userGroupSearchCfg 是用户组的搜索配置；表别名 r/a 需与各 handler 追加的 where 条件保持一致。
var userGroupSearchCfg = search.SearchConfig{
	Table: "roles r JOIN oauth_apps a ON a.id = r.app_id",
	Item:  "用户组",
	Columns: []string{
		"r.id", "r.app_id", "a.namespace AS app_namespace", "r.name", "r.note",
		"r.is_public", "r.created_at", "r.updated_at",
	},
	Fields: []search.Field{
		{ID: "id", Column: "r.id", Numeric: true},
		{ID: "app_id", Column: "r.app_id", Numeric: true},
		{ID: "app_namespace", Column: "a.namespace"},
		{ID: "name", Column: "r.name"},
		{ID: "note", Column: "r.note"},
	},
	MatchMethods: search.MatchMethodValues(),
	SortableFields: []search.Field{
		{ID: "id", Column: "r.id"},
		{ID: "name", Column: "r.name"},
		{ID: "created_at", Column: "r.created_at"},
	},
	Tags: []search.Tag{
		{ID: "public", Column: "r.is_public", ValueMap: search.ValueMapOf([]string{"true", "false"})},
	},
	DefaultSortColumn: "r.id",
}

// permissionSearchRow 是权限定义搜索的数据行，db 标签需与 permissionSearchCfg.Columns 对应。
type permissionSearchRow struct {
	ID          int64      `db:"id"`
	AppID       int64      `db:"app_id"`
	Namespace   string     `db:"namespace"`
	Value       string     `db:"value"`
	Description string     `db:"description"`
	Requestable bool       `db:"requestable"`
	CreatedBy   null.Int64 `db:"created_by"`
	CreatedAt   time.Time  `db:"created_at"`
	UpdatedAt   time.Time  `db:"updated_at"`
}

// userGroupSearchRow 是用户组搜索的数据行，db 标签需与 userGroupSearchCfg.Columns 对应。
type userGroupSearchRow struct {
	ID           int64     `db:"id"`
	AppID        int64     `db:"app_id"`
	AppNamespace string    `db:"app_namespace"`
	Name         string    `db:"name"`
	Note         string    `db:"note"`
	Public       bool      `db:"is_public"`
	CreatedAt    time.Time `db:"created_at"`
	UpdatedAt    time.Time `db:"updated_at"`
}

// ---------------------------------------------------------------------------
// 权限定义搜索
// ---------------------------------------------------------------------------

// permissionSearchInfoHandler 返回全局权限定义搜索的可查询字段与排序信息。
func permissionSearchInfoHandler(c *gin.Context) *errs.Error {
	c.JSON(http.StatusOK, search.GetInfo(&permissionSearchCfg))
	return nil
}

// permissionSearchQueryHandler 执行全局权限定义搜索；已删除应用下的定义不参与搜索。
func permissionSearchQueryHandler(c *gin.Context) *errs.Error {
	return runPermissionSearch(c, []sq.Sqlizer{sq.Expr("a.deleted_at IS NULL")})
}

// appPermissionSearchInfoHandler 返回应用范围内权限定义搜索的可查询字段信息。
func appPermissionSearchInfoHandler(c *gin.Context) *errs.Error {
	if _, err := handling.ResolveApp(c); err != nil {
		return err
	}
	c.JSON(http.StatusOK, search.GetInfo(&permissionSearchCfg))
	return nil
}

// appPermissionSearchQueryHandler 在指定应用范围内执行权限定义搜索。
func appPermissionSearchQueryHandler(c *gin.Context) *errs.Error {
	app, err := handling.ResolveApp(c)
	if err != nil {
		return err
	}
	return runPermissionSearch(c, []sq.Sqlizer{
		sq.Eq{"pd.app_id": app.ID},
		sq.Expr("a.deleted_at IS NULL"),
	})
}

// runPermissionSearch 绑定搜索请求、合并附加过滤条件并执行查询，最后把结果行渲染为带完整权限串的响应。
func runPermissionSearch(c *gin.Context, where []sq.Sqlizer) *errs.Error {
	var req search.SearchRequest
	if e := c.ShouldBindJSON(&req); e != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}

	cfg := permissionSearchCfg
	cfg.AdditionalWhere = where

	result, err := search.ExecSearch[permissionSearchRow](c.Request.Context(), &cfg, &req)
	if err != nil {
		return err
	}

	// 结果行渲染：补上命名空间与完整权限串
	data := make([]gin.H, 0, len(result.Data))
	for _, row := range result.Data {
		data = append(data, gin.H{
			"id":          row.ID,
			"app_id":      row.AppID,
			"namespace":   row.Namespace,
			"permission":  perm.Render(row.Namespace, row.Value),
			"value":       row.Value,
			"description": row.Description,
			"requestable": row.Requestable,
			"created_by":  row.CreatedBy,
			"created_at":  row.CreatedAt,
			"updated_at":  row.UpdatedAt,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"count": result.Count,
		"data":  data,
	})
	return nil
}

// ---------------------------------------------------------------------------
// 用户组搜索
// ---------------------------------------------------------------------------

// userGroupSearchInfoHandler 返回全局用户组搜索的可查询字段与排序信息。
func userGroupSearchInfoHandler(c *gin.Context) *errs.Error {
	c.JSON(http.StatusOK, search.GetInfo(&userGroupSearchCfg))
	return nil
}

// userGroupSearchQueryHandler 执行全局用户组搜索；已删除应用下的用户组不参与搜索。
func userGroupSearchQueryHandler(c *gin.Context) *errs.Error {
	return runUserGroupSearch(c, []sq.Sqlizer{sq.Expr("a.deleted_at IS NULL")})
}

// appUserGroupSearchInfoHandler 返回应用范围内用户组搜索的可查询字段信息。
func appUserGroupSearchInfoHandler(c *gin.Context) *errs.Error {
	if _, err := handling.ResolveApp(c); err != nil {
		return err
	}
	c.JSON(http.StatusOK, search.GetInfo(&userGroupSearchCfg))
	return nil
}

// appUserGroupSearchQueryHandler 在应用范围内执行用户组搜索：可见范围为本应用的用户组加上其他应用的公开用户组。
func appUserGroupSearchQueryHandler(c *gin.Context) *errs.Error {
	app, err := handling.ResolveApp(c)
	if err != nil {
		return err
	}
	// 可见范围：本应用用户组 ∪ 其他应用的公开用户组。
	return runUserGroupSearch(c, []sq.Sqlizer{
		sq.Or{sq.Eq{"r.app_id": app.ID}, sq.Eq{"r.is_public": true}},
		sq.Expr("a.deleted_at IS NULL"),
	})
}

// runUserGroupSearch 绑定搜索请求、合并附加过滤条件并执行查询，最后把结果行渲染为响应。
func runUserGroupSearch(c *gin.Context, where []sq.Sqlizer) *errs.Error {
	var req search.SearchRequest
	if e := c.ShouldBindJSON(&req); e != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}

	cfg := userGroupSearchCfg
	cfg.AdditionalWhere = where

	result, err := search.ExecSearch[userGroupSearchRow](c.Request.Context(), &cfg, &req)
	if err != nil {
		return err
	}

	// 结果行渲染
	data := make([]gin.H, 0, len(result.Data))
	for _, row := range result.Data {
		data = append(data, gin.H{
			"id":            row.ID,
			"app_id":        row.AppID,
			"app_namespace": row.AppNamespace,
			"name":          row.Name,
			"note":          row.Note,
			"public":        row.Public,
			"created_at":    row.CreatedAt,
			"updated_at":    row.UpdatedAt,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"count": result.Count,
		"data":  data,
	})
	return nil
}
