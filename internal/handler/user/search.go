package user

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/perm"
	"fdfz-student-id/internal/search"
	"net/http"

	"github.com/gin-gonic/gin"
)

var searchCfg = search.SearchConfig{
	Table:             "users",
	Item:              "用户",
	Fields:            []search.Field{{ID: "id", Column: "id"}, {ID: "username", Column: "username"}, {ID: "nickname", Column: "nickname"}, {ID: "student_num", Column: "student_num"}},
	MatchMethods:      search.MatchMethodValues(),
	SortableFields:    []search.Field{{ID: "username", Column: "username"}, {ID: "nickname", Column: "nickname"}, {ID: "student_num", Column: "student_num"}, {ID: "created_at", Column: "created_at"}},
	Tags:              []search.Tag{{ID: "type", Column: "type", ValueMap: search.ValueMapOf(model.UserTypeNames())}, {ID: "school", Column: "school", ValueMap: search.ValueMapOf(model.SchoolNames())}},
	DefaultSortColumn: "id",
}

var searchInfo = search.GetInfo(&searchCfg)

func SearchInfoHandler(c *gin.Context) {
	claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)
	if !perm.Contains(claims.Permissions, "student_id.users.list") {
		errs.PermissionDeniedError().AppendDetails("权限不足", "鉴权失败").Respond(c)
		return
	}
	c.JSON(http.StatusOK, searchInfo)
}

func SearchQueryHandler(c *gin.Context) {
	var req search.SearchRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errs.BadRequestError().AppendDetails("请求解析失败", "用户搜索失败").Respond(c)
		return
	}

	claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)
	if !perm.Contains(claims.Permissions, "student_id.users.list") {
		errs.PermissionDeniedError().AppendDetails("权限不足", "鉴权失败").Respond(c)
		return
	}

	users, err := search.ExecSearch[model.User](c, &searchCfg, &req)
	if err != nil {
		err.AppendDetails("用户搜索失败").Respond(c)
		return
	}

	c.JSON(http.StatusOK, filterProfiles(claims, users.Data...))
}
