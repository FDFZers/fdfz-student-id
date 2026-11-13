package app

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/service/perm"
	"fdfz-student-id/internal/service/search"
	"fdfz-student-id/internal/util/handling"
	"net/http"

	sq "github.com/Masterminds/squirrel"
	"github.com/gin-gonic/gin"
)

// appSearchCfg 是应用搜索配置；Table 只含 oauth_apps，附加条件由 handler 按调用方范围注入。
var appSearchCfg = search.SearchConfig{
	Table: "oauth_apps",
	Item:  "应用",
	Columns: []string{
		"id", "namespace", "owner_user_id", "secret_hash", "name", "description",
		"homepage_url", "client_type", "redirect_uris", "requested_perms", "status",
		"created_at", "updated_at",
	},
	Fields: []search.Field{
		{ID: "id", Column: "id", Numeric: true},
		{ID: "namespace", Column: "namespace"},
		{ID: "owner_user_id", Column: "owner_user_id", Numeric: true},
		{ID: "name", Column: "name"},
		{ID: "description", Column: "description"},
		{ID: "homepage_url", Column: "homepage_url"},
	},
	MatchMethods: search.MatchMethodValues(),
	SortableFields: []search.Field{
		{ID: "id", Column: "id"},
		{ID: "namespace", Column: "namespace"},
		{ID: "name", Column: "name"},
		{ID: "created_at", Column: "created_at"},
		{ID: "updated_at", Column: "updated_at"},
	},
	Tags: []search.Tag{
		{ID: "status", Column: "status", ValueMap: search.ValueMapOf(model.AppStatusNames())},
		{ID: "client_type", Column: "client_type", ValueMap: search.ValueMapOf(model.AppTypeNames())},
	},
	DefaultSortColumn: "id",
}

// appSearchConfigForClaims 按调用方范围生成搜索配置：
// 全局管理员可搜索全部应用；普通所有者只能搜索自己名下的应用。
func appSearchConfigForClaims(claims *model.RegisteredTokenClaims) (*search.SearchConfig, *errs.Error) {
	cfg := appSearchCfg
	where := []sq.Sqlizer{sq.Expr("deleted_at IS NULL")}

	if !handling.IsGlobalAppReader(claims) {
		if !perm.HasPermission(claims, perm.PermAppRead) {
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

	c.JSON(http.StatusOK, search.GetInfo(cfg))
	return nil
}

// appSearchQueryHandler 执行应用搜索并返回总数与应用信息；不会返回密钥哈希。
func appSearchQueryHandler(c *gin.Context) *errs.Error {
	var req search.SearchRequest
	if e := c.ShouldBindJSON(&req); e != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}

	claims := handling.MustGetClaims(c)
	cfg, err := appSearchConfigForClaims(claims)
	if err != nil {
		return err
	}

	result, err := search.ExecSearch[model.OAuthApp](c.Request.Context(), cfg, &req)
	if err != nil {
		return err
	}

	c.JSON(http.StatusOK, gin.H{
		"count": result.Count,
		"data":  appsJSON(result.Data),
	})
	return nil
}
