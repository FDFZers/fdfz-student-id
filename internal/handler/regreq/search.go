package regreq

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/service/perm"
	"fdfz-student-id/internal/service/search"
	"fdfz-student-id/internal/util/handling"
	"net/http"

	"github.com/gin-gonic/gin"
)

// searchCfg 注册申请搜索配置：可搜索字段、可排序字段、标签（状态/用户类型/学校）与返回列。
// 注意：Columns 不包含 password（密码哈希），模型的 Password 字段保持零值，不读取也不对外返回。
var searchCfg = search.SearchConfig{
	Table:             "register_requests",
	Item:              "注册请求",
	Columns:           []string{"id", "username", "nickname", "type", "student_num", "real_name", "school", "created_at", "status", "created_user_id", "reviewer_user_id", "review_comment", "reviewed_at"},
	Fields:            []search.Field{{ID: "id", Column: "id", Numeric: true}, {ID: "student_num", Column: "student_num"}, {ID: "real_name", Column: "real_name"}, {ID: "created_user_id", Column: "created_user_id", Numeric: true}},
	MatchMethods:      search.MatchMethodValues(),
	SortableFields:    []search.Field{{ID: "created_at", Column: "created_at"}, {ID: "reviewed_at", Column: "reviewed_at"}},
	Tags:              []search.Tag{{ID: "status", Column: "status", ValueMap: search.ValueMapOf(model.RegisterRequestStatusNames())}, {ID: "type", Column: "type", ValueMap: search.ValueMapOf(model.UserTypeNames())}, {ID: "school", Column: "school", ValueMap: search.ValueMapOf(model.SchoolNames())}},
	DefaultSortColumn: "id",
}

// searchInfo 注册申请搜索能力的静态描述，供前端渲染搜索表单。
var searchInfo = search.GetInfo(&searchCfg)

// SearchInfoHandler 返回注册申请搜索的字段、匹配方法、可排序字段与标签取值；需要 register_requests.list 权限。
func SearchInfoHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)
	if !perm.HasPermission(claims, perm.PermRegisterRequestList) {
		return errs.PermissionDeniedError().AppendDetails("权限不足").Seal()
	}
	c.JSON(http.StatusOK, searchInfo)
	return nil
}

// SearchQueryHandler 执行注册申请搜索，返回总数与申请摘要（不含密码哈希）；需要 register_requests.list 权限。
func SearchQueryHandler(c *gin.Context) *errs.Error {
	var req search.SearchRequest
	if e := c.ShouldBindJSON(&req); e != nil {
		return errs.BadRequestError().AppendDetails("请求解析失败")
	}

	claims := handling.MustGetClaims(c)
	if !perm.HasPermission(claims, perm.PermRegisterRequestList) {
		return errs.PermissionDeniedError().AppendDetails("权限不足").Seal()
	}

	requests, err := search.ExecSearch[model.RegisterRequest](c.Request.Context(), &searchCfg, &req)
	if err != nil {
		return err
	}

	// 逐条构造对外字段；password 不在查询列中

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
