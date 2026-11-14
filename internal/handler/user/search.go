package user

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	permsvc "fdfz-student-id/internal/service/perm"
	searchsvc "fdfz-student-id/internal/service/search"
	"fdfz-student-id/internal/util/handling"
	"net/http"

	"github.com/gin-gonic/gin"
)

// searchCfg 用户搜索配置：可搜索字段、可排序字段、标签（用户类型/学校）与返回列。
// 查询结果交给 usersJSON 过滤，因此 SQL 返回的完整用户记录不会被直接暴露给前端。
var searchCfg = searchsvc.SearchConfig{
	Table:             "users",
	Item:              "用户",
	Columns:           []string{"id", "username", "type", "student_num", "real_name", "school", "nickname", "signature", "bio", "visibilities", "created_at", "updated_at", "deleted_at"},
	Fields:            []searchsvc.Field{{ID: "id", Column: "id", Numeric: true}, {ID: "username", Column: "username"}, {ID: "nickname", Column: "nickname"}, {ID: "student_num", Column: "student_num"}},
	MatchMethods:      searchsvc.MatchMethodValues(),
	SortableFields:    []searchsvc.Field{{ID: "username", Column: "username"}, {ID: "nickname", Column: "nickname"}, {ID: "student_num", Column: "student_num"}, {ID: "created_at", Column: "created_at"}},
	Tags:              []searchsvc.Tag{{ID: "type", Column: "type", ValueMap: searchsvc.ValueMapOf(model.UserTypeNames())}, {ID: "school", Column: "school", ValueMap: searchsvc.ValueMapOf(model.SchoolNames())}},
	DefaultSortColumn: "id",
}

// removeSearchFields 返回过滤后的字段副本，不修改入参。
func removeSearchFields(fields []searchsvc.Field, ids ...string) []searchsvc.Field {
	removed := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		removed[id] = struct{}{}
	}
	result := make([]searchsvc.Field, 0, len(fields))
	for _, field := range fields {
		if _, ok := removed[field.ID]; ok {
			continue
		}
		result = append(result, field)
	}
	return result
}

// searchConfigForClaims 按资料读权限返回裁剪后的搜索配置副本，防止用搜索计数探测不可读字段。
func searchConfigForClaims(claims *model.RegisteredTokenClaims) *searchsvc.SearchConfig {
	cfg := searchCfg
	if !permsvc.HasPermission(claims, permsvc.PermUsersProfileReadBasic) {
		cfg.Fields = removeSearchFields(cfg.Fields, "username", "nickname")
		cfg.SortableFields = removeSearchFields(cfg.SortableFields, "username", "nickname")
	}
	if !permsvc.HasPermission(claims, permsvc.PermUsersProfileReadIdentity) {
		cfg.Fields = removeSearchFields(cfg.Fields, "student_num")
		cfg.SortableFields = removeSearchFields(cfg.SortableFields, "student_num")
	}
	return &cfg
}

// searchInfoHandler 返回用户搜索的字段、匹配方法、可排序字段与标签取值。
func searchInfoHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)
	c.JSON(http.StatusOK, searchsvc.GetInfo(searchConfigForClaims(claims)))
	return nil
}

// searchQueryHandler 执行用户搜索并返回总数与过滤后的用户资料；需要 users.list 权限。
// 搜索会返回已软删除用户（deleted_at 非空），由 usersJSON 输出 deleted 标记。
func searchQueryHandler(c *gin.Context) *errs.Error {
	var req searchsvc.SearchRequest
	if err := handling.BindJSON(c, &req); err != nil {
		return err
	}

	claims := handling.MustGetClaims(c)
	cfg := searchConfigForClaims(claims)
	users, err := searchsvc.ExecSearch[model.User](c.Request.Context(), cfg, &req)
	if err != nil {
		return err
	}

	filtered, err := handling.UsersJSON(c.Request.Context(), claims, users.Data...)
	if err != nil {
		return err
	}

	handling.RespondList(c, users.Count, filtered)
	return nil
}
