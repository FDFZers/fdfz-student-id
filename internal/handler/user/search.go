package user

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/service/search"
	"fdfz-student-id/internal/util/handling"
	"net/http"

	"github.com/gin-gonic/gin"
)

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

var searchInfo = search.GetInfo(&searchCfg)

func searchInfoHandler(c *gin.Context) *errs.Error {
	c.JSON(http.StatusOK, searchInfo)
	return nil
}

func searchQueryHandler(c *gin.Context) *errs.Error {
	var req search.SearchRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}

	claims := handling.MustGetClaims(c)
	users, err := search.ExecSearch[model.User](c, &searchCfg, &req)
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
