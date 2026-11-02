package regreq

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/service/perm"
	search2 "fdfz-student-id/internal/service/search"
	"net/http"

	"github.com/gin-gonic/gin"
)

var searchCfg = search2.SearchConfig{
	Table:             "register_requests",
	Item:              "注册请求",
	Columns:           []string{"id", "username", "nickname", "type", "student_num", "real_name", "school", "password", "created_at", "status", "created_user_id", "reviewer_user_id", "review_comment", "reviewed_at"},
	Fields:            []search2.Field{{ID: "id", Column: "id", Numeric: true}, {ID: "student_num", Column: "student_num"}, {ID: "real_name", Column: "real_name"}, {ID: "created_user_id", Column: "created_user_id", Numeric: true}},
	MatchMethods:      search2.MatchMethodValues(),
	SortableFields:    []search2.Field{{ID: "created_at", Column: "created_at"}, {ID: "reviewed_at", Column: "reviewed_at"}},
	Tags:              []search2.Tag{{ID: "status", Column: "status", ValueMap: search2.ValueMapOf(model.RegisterRequestStatusNames())}, {ID: "type", Column: "type", ValueMap: search2.ValueMapOf(model.UserTypeNames())}, {ID: "school", Column: "school", ValueMap: search2.ValueMapOf(model.SchoolNames())}},
	DefaultSortColumn: "id",
}

var searchInfo = search2.GetInfo(&searchCfg)

func SearchInfoHandler(c *gin.Context) *errs.Error {
	claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)
	if !perm.Contains(claims.Permissions, "student_id.register_requests.list") {
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
	if !perm.Contains(claims.Permissions, "student_id.register_requests.list") {
		return errs.PermissionDeniedError().AppendDetails("权限不足", "鉴权失败").Seal()
	}

	requests, err := search2.ExecSearch[model.RegisterRequest](c, &searchCfg, &req)
	if err != nil {
		return err
	}

	filtered := make([]*gin.H, 0, len(requests.Data))
	for _, request := range requests.Data {
		filtered = append(filtered, &gin.H{
			"id":               request.ID,
			"type":             request.Type,
			"student_num":      request.StudentNum,
			"real_name":        request.RealName,
			"school":           request.School,
			"username":         request.Username,
			"nickname":         request.Nickname,
			"created_at":       request.CreatedAt,
			"status":           request.Status,
			"created_user_id":  request.CreatedUserID,
			"reviewer_user_id": request.ReviewerUserID,
			"review_comment":   request.ReviewComment,
			"reviewed_at":      request.ReviewedAt,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"count": requests.Count,
		"data":  filtered,
	})
	return nil
}
