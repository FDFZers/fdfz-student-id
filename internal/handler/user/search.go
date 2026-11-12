package user

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/service/perm"
	"fdfz-student-id/internal/service/search"
	"fdfz-student-id/internal/util/handling"
	"net/http"

	"github.com/gin-gonic/gin"
)

// searchCfg 用户搜索配置：可搜索字段、可排序字段、标签（用户类型/学校）与返回列。
// 查询结果交给 filterProfiles 过滤，因此 SQL 返回的完整用户记录不会被直接暴露给前端。
var searchCfg = search.SearchConfig{
	Table:             "users",
	Item:              "用户",
	Columns:           []string{"id", "username", "type", "student_num", "real_name", "school", "nickname", "signature", "bio", "visibilities", "created_at", "updated_at", "deleted_at"},
	Fields:            []search.Field{{ID: "id", Column: "id", Numeric: true}, {ID: "username", Column: "username"}, {ID: "nickname", Column: "nickname"}, {ID: "student_num", Column: "student_num"}},
	MatchMethods:      search.MatchMethodValues(),
	SortableFields:    []search.Field{{ID: "username", Column: "username"}, {ID: "nickname", Column: "nickname"}, {ID: "student_num", Column: "student_num"}, {ID: "created_at", Column: "created_at"}},
	Tags:              []search.Tag{{ID: "type", Column: "type", ValueMap: search.ValueMapOf(model.UserTypeNames())}, {ID: "school", Column: "school", ValueMap: search.ValueMapOf(model.SchoolNames())}},
	DefaultSortColumn: "id",
}

// removeSearchFields 返回过滤后的字段副本，不修改入参。
func removeSearchFields(fields []search.Field, ids ...string) []search.Field {
	removed := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		removed[id] = struct{}{}
	}
	result := make([]search.Field, 0, len(fields))
	for _, field := range fields {
		if _, ok := removed[field.ID]; ok {
			continue
		}
		result = append(result, field)
	}
	return result
}

// searchConfigForClaims 按资料读权限返回裁剪后的搜索配置副本，防止用搜索计数探测不可读字段。
func searchConfigForClaims(claims *model.RegisteredTokenClaims) *search.SearchConfig {
	cfg := searchCfg
	if !perm.HasPermission(claims, perm.PermUsersProfileReadBasic) {
		cfg.Fields = removeSearchFields(cfg.Fields, "username", "nickname")
		cfg.SortableFields = removeSearchFields(cfg.SortableFields, "username", "nickname")
	}
	if !perm.HasPermission(claims, perm.PermUsersProfileReadIdentity) {
		cfg.Fields = removeSearchFields(cfg.Fields, "student_num")
		cfg.SortableFields = removeSearchFields(cfg.SortableFields, "student_num")
	}
	return &cfg
}

// searchInfoHandler 返回用户搜索的字段、匹配方法、可排序字段与标签取值。
func searchInfoHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)
	c.JSON(http.StatusOK, search.GetInfo(searchConfigForClaims(claims)))
	return nil
}

// searchQueryHandler 执行用户搜索并返回总数与过滤后的用户资料；需要 users.list 权限。
// 注意：搜索会返回已软删除用户（deleted_at 非空），由 filterProfiles 输出 deleted 标记。
func searchQueryHandler(c *gin.Context) *errs.Error {
	var req search.SearchRequest
	if e := c.ShouldBindJSON(&req); e != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}

	claims := handling.MustGetClaims(c)
	cfg := searchConfigForClaims(claims)
	users, err := search.ExecSearch[model.User](c.Request.Context(), cfg, &req)
	if err != nil {
		return err
	}

	filtered, err := filterProfiles(c.Request.Context(), claims, users.Data...)
	if err != nil {
		return err
	}

	c.JSON(http.StatusOK, gin.H{
		"count": users.Count,
		"data":  filtered,
	})
	return nil
}
