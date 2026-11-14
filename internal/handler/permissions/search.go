package permissions

import (
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/util/handling"
	"net/http"
	"time"

	"fdfz-student-id/internal/errs"
	searchsvc "fdfz-student-id/internal/service/search"

	sq "github.com/Masterminds/squirrel"
	"github.com/gin-gonic/gin"
	"github.com/guregu/null/v6"
)

// permissionSearchCfg 是权限定义的搜索配置：可查询字段、排序字段、标签与默认排序。
// 表别名 pd/a 需与各 handler 追加的 where 条件保持一致。
var permissionSearchCfg = searchsvc.SearchConfig{
	Table: "permission_defs pd JOIN apps a ON a.id = pd.app_id",
	Item:  "权限定义",
	Columns: []string{
		"pd.id", "pd.app_id", "a.namespace", "pd.value", "pd.description",
		"pd.requestable", "pd.created_by", "pd.created_at", "pd.updated_at",
	},
	Fields: []searchsvc.Field{
		{ID: "id", Column: "pd.id", Numeric: true},
		{ID: "app_id", Column: "pd.app_id", Numeric: true},
		{ID: "namespace", Column: "a.namespace"},
		{ID: "value", Column: "pd.value"},
		{ID: "description", Column: "pd.description"},
	},
	MatchMethods: searchsvc.MatchMethodValues(),
	SortableFields: []searchsvc.Field{
		{ID: "id", Column: "pd.id"},
		{ID: "value", Column: "pd.value"},
		{ID: "created_at", Column: "pd.created_at"},
	},
	Tags: []searchsvc.Tag{
		{ID: "requestable", Column: "pd.requestable", ValueMap: searchsvc.ValueMapOf([]string{"true", "false"})},
	},
	DefaultSortColumn: "pd.id",
}

// userGroupSearchCfg 是用户组的搜索配置；表别名 r/a 需与各 handler 追加的 where 条件保持一致。
var userGroupSearchCfg = searchsvc.SearchConfig{
	Table: "roles r JOIN apps a ON a.id = r.app_id",
	Item:  "用户组",
	Columns: []string{
		"r.id", "r.app_id", "a.namespace AS app_namespace", "r.name", "r.note",
		"r.is_public", "r.is_system", "r.created_at", "r.updated_at",
	},
	Fields: []searchsvc.Field{
		{ID: "id", Column: "r.id", Numeric: true},
		{ID: "app_id", Column: "r.app_id", Numeric: true},
		{ID: "app_namespace", Column: "a.namespace"},
		{ID: "name", Column: "r.name"},
		{ID: "note", Column: "r.note"},
	},
	MatchMethods: searchsvc.MatchMethodValues(),
	SortableFields: []searchsvc.Field{
		{ID: "id", Column: "r.id"},
		{ID: "name", Column: "r.name"},
		{ID: "created_at", Column: "r.created_at"},
	},
	Tags: []searchsvc.Tag{
		{ID: "public", Column: "r.is_public", ValueMap: searchsvc.ValueMapOf([]string{"true", "false"})},
		{ID: "system", Column: "r.is_system", ValueMap: searchsvc.ValueMapOf([]string{"true", "false"})},
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
	System       bool      `db:"is_system"`
	CreatedAt    time.Time `db:"created_at"`
	UpdatedAt    time.Time `db:"updated_at"`
}

// ---------------------------------------------------------------------------
// 权限定义搜索
// ---------------------------------------------------------------------------

// permissionSearchInfoHandler 返回全局权限定义搜索的可查询字段与排序信息。
func permissionSearchInfoHandler(c *gin.Context) *errs.Error {
	c.JSON(http.StatusOK, searchsvc.GetInfo(&permissionSearchCfg))
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
	c.JSON(http.StatusOK, searchsvc.GetInfo(&permissionSearchCfg))
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
	var req searchsvc.SearchRequest
	if err := handling.BindJSON(c, &req); err != nil {
		return err
	}

	cfg := permissionSearchCfg
	cfg.AdditionalWhere = where

	result, err := searchsvc.ExecSearch[permissionSearchRow](c.Request.Context(), &cfg, &req)
	if err != nil {
		return err
	}

	// 结果行渲染：补上命名空间与完整权限串
	data := make([]gin.H, 0, len(result.Data))
	for _, row := range result.Data {
		def := &model.PermissionDef{
			ID:          row.ID,
			AppID:       row.AppID,
			Value:       row.Value,
			Description: row.Description,
			Requestable: row.Requestable,
			CreatedBy:   row.CreatedBy,
			CreatedAt:   row.CreatedAt,
			UpdatedAt:   row.UpdatedAt,
		}
		data = append(data, handling.DefJSON(def, row.Namespace))
	}

	handling.RespondList(c, result.Count, data)
	return nil
}

// ---------------------------------------------------------------------------
// 用户组搜索
// ---------------------------------------------------------------------------

// userGroupSearchInfoHandler 返回全局用户组搜索的可查询字段与排序信息。
func userGroupSearchInfoHandler(c *gin.Context) *errs.Error {
	c.JSON(http.StatusOK, searchsvc.GetInfo(&userGroupSearchCfg))
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
	c.JSON(http.StatusOK, searchsvc.GetInfo(&userGroupSearchCfg))
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
	var req searchsvc.SearchRequest
	if err := handling.BindJSON(c, &req); err != nil {
		return err
	}

	cfg := userGroupSearchCfg
	cfg.AdditionalWhere = where

	result, err := searchsvc.ExecSearch[userGroupSearchRow](c.Request.Context(), &cfg, &req)
	if err != nil {
		return err
	}

	// 结果行渲染
	data := make([]gin.H, 0, len(result.Data))
	for _, row := range result.Data {
		role := &model.Role{
			ID:        row.ID,
			AppID:     row.AppID,
			Name:      row.Name,
			Note:      row.Note,
			Public:    row.Public,
			System:    row.System,
			CreatedAt: row.CreatedAt,
			UpdatedAt: row.UpdatedAt,
		}
		data = append(data, handling.GroupSearchJSON(role, row.AppNamespace))
	}

	handling.RespondList(c, result.Count, data)
	return nil
}
