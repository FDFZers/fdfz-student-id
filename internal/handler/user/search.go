package user

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/service/perm"
	search2 "fdfz-student-id/internal/service/search"
	"net/http"

	"github.com/gin-gonic/gin"
)

var searchCfg = search2.SearchConfig{
	Table:             "users",
	Item:              "用户",
	Columns:           []string{"id", "username", "type", "student_num", "real_name", "school", "nickname", "signature", "bio", "visibilities", "created_at", "updated_at", "deleted_at"},
	Fields:            []search2.Field{{ID: "id", Column: "id", Numeric: true}, {ID: "username", Column: "username"}, {ID: "nickname", Column: "nickname"}, {ID: "student_num", Column: "student_num"}},
	MatchMethods:      search2.MatchMethodValues(),
	SortableFields:    []search2.Field{{ID: "username", Column: "username"}, {ID: "nickname", Column: "nickname"}, {ID: "student_num", Column: "student_num"}, {ID: "created_at", Column: "created_at"}},
	Tags:              []search2.Tag{{ID: "type", Column: "type", ValueMap: search2.ValueMapOf(model.UserTypeNames())}, {ID: "school", Column: "school", ValueMap: search2.ValueMapOf(model.SchoolNames())}},
	DefaultSortColumn: "id",
}

var searchInfo = search2.GetInfo(&searchCfg)

func SearchInfoHandler(c *gin.Context) *errs.Error {
	claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)
	if !perm.Contains(claims.Permissions, "student_id.users.list") {
		return errs.PermissionDeniedError().AppendDetails("权限不足", "鉴权失败").Seal()
	}
	c.JSON(http.StatusOK, searchInfo)
	return nil
}

func SearchQueryHandler(c *gin.Context) *errs.Error {
	var req search2.SearchRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}

	claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)
	if !perm.Contains(claims.Permissions, "student_id.users.list") {
		return errs.PermissionDeniedError().AppendDetails("权限不足", "鉴权失败").Seal()
	}

	users, err := search2.ExecSearch[model.User](c, &searchCfg, &req)
	if err != nil {
		return err
	}

	c.JSON(http.StatusOK, gin.H{
		"count": users.Count,
		"data":  filterProfiles(claims, users.Data...),
	})
	return nil
}
