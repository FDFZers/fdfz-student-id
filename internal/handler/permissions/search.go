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

func permissionSearchInfoHandler(c *gin.Context) *errs.Error {
	c.JSON(http.StatusOK, search.GetInfo(&permissionSearchCfg))
	return nil
}

func permissionSearchQueryHandler(c *gin.Context) *errs.Error {
	return runPermissionSearch(c, []sq.Sqlizer{sq.Expr("a.deleted_at IS NULL")})
}

func appPermissionSearchInfoHandler(c *gin.Context) *errs.Error {
	if _, err := handling.ResolveApp(c); err != nil {
		return err
	}
	c.JSON(http.StatusOK, search.GetInfo(&permissionSearchCfg))
	return nil
}

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

func runPermissionSearch(c *gin.Context, where []sq.Sqlizer) *errs.Error {
	var req search.SearchRequest
	if bindErr := c.ShouldBindJSON(&req); bindErr != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}

	cfg := permissionSearchCfg
	cfg.AdditionalWhere = where

	result, err := search.ExecSearch[permissionSearchRow](c.Request.Context(), &cfg, &req)
	if err != nil {
		return err
	}

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

func userGroupSearchInfoHandler(c *gin.Context) *errs.Error {
	c.JSON(http.StatusOK, search.GetInfo(&userGroupSearchCfg))
	return nil
}

func userGroupSearchQueryHandler(c *gin.Context) *errs.Error {
	return runUserGroupSearch(c, []sq.Sqlizer{sq.Expr("a.deleted_at IS NULL")})
}

func appUserGroupSearchInfoHandler(c *gin.Context) *errs.Error {
	if _, err := handling.ResolveApp(c); err != nil {
		return err
	}
	c.JSON(http.StatusOK, search.GetInfo(&userGroupSearchCfg))
	return nil
}

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

func runUserGroupSearch(c *gin.Context, where []sq.Sqlizer) *errs.Error {
	var req search.SearchRequest
	if bindErr := c.ShouldBindJSON(&req); bindErr != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}

	cfg := userGroupSearchCfg
	cfg.AdditionalWhere = where

	result, err := search.ExecSearch[userGroupSearchRow](c.Request.Context(), &cfg, &req)
	if err != nil {
		return err
	}

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
