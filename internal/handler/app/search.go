package app

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	permsvc "fdfz-student-id/internal/service/perm"
	searchsvc "fdfz-student-id/internal/service/search"
	"fdfz-student-id/internal/util/handling"
	"net/http"

	sq "github.com/Masterminds/squirrel"
	"github.com/gin-gonic/gin"
)

// appSearchCfg 是应用搜索配置；附加条件由 handler 按调用方范围注入。
var appSearchCfg = searchsvc.SearchConfig{
	Table: "apps",
	Item:  "应用",
	Columns: []string{
		"id", "namespace", "owner_user_id", "secret_hash", "name", "description",
		"homepage_url", "client_type", "redirect_uris", "requested_perms", "status",
		"created_at", "updated_at",
	},
	Fields: []searchsvc.Field{
		{ID: "id", Column: "id", Numeric: true},
		{ID: "namespace", Column: "namespace"},
		{ID: "owner_user_id", Column: "owner_user_id", Numeric: true},
		{ID: "name", Column: "name"},
		{ID: "description", Column: "description"},
		{ID: "homepage_url", Column: "homepage_url"},
	},
	MatchMethods: searchsvc.MatchMethodValues(),
	SortableFields: []searchsvc.Field{
		{ID: "id", Column: "id"},
		{ID: "namespace", Column: "namespace"},
		{ID: "name", Column: "name"},
		{ID: "created_at", Column: "created_at"},
		{ID: "updated_at", Column: "updated_at"},
	},
	Tags: []searchsvc.Tag{
		{ID: "status", Column: "status", ValueMap: searchsvc.ValueMapOf(model.AppStatusNames())},
		{ID: "client_type", Column: "client_type", ValueMap: searchsvc.ValueMapOf(model.AppTypeNames())},
	},
	DefaultSortColumn: "id",
}

// appSearchConfigForClaims 按调用方范围生成搜索配置：管理员可搜索全部应用，所有者只能搜索自己名下的应用。
func appSearchConfigForClaims(claims *model.RegisteredTokenClaims) (*searchsvc.SearchConfig, *errs.Error) {
	cfg := appSearchCfg
	where := []sq.Sqlizer{sq.Expr("deleted_at IS NULL")}

	if !handling.IsGlobalAppReader(claims) {
		if !permsvc.HasPermission(claims, permsvc.PermAppRead) {
			return nil, errs.PermissionDeniedError().AppendDetails("权限不足").Seal()
		}
		where = append(where, sq.Eq{"owner_user_id": claims.UserID})
	}

	cfg.AdditionalWhere = where
	return &cfg, nil
}

// appSearchInfoHandler 返回应用搜索的可查询字段、匹配方法、排序字段与标签。
func appSearchInfoHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)
	cfg, err := appSearchConfigForClaims(claims)
	if err != nil {
		return err
	}

	c.JSON(http.StatusOK, searchsvc.GetInfo(cfg))
	return nil
}

// appSearchQueryHandler 执行应用搜索并返回总数与应用信息；不会返回密钥哈希。
func appSearchQueryHandler(c *gin.Context) *errs.Error {
	var req searchsvc.SearchRequest
	if err := handling.BindJSON(c, &req); err != nil {
		return err
	}

	claims := handling.MustGetClaims(c)
	cfg, err := appSearchConfigForClaims(claims)
	if err != nil {
		return err
	}

	result, err := searchsvc.ExecSearch[model.OAuthApp](c.Request.Context(), cfg, &req)
	if err != nil {
		return err
	}

	handling.RespondList(c, result.Count, handling.AppsJSON(result.Data))
	return nil
}
