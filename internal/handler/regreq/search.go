package regreq

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	permsvc "fdfz-student-id/internal/service/perm"
	searchsvc "fdfz-student-id/internal/service/search"
	"fdfz-student-id/internal/util/handling"
	"net/http"

	"github.com/gin-gonic/gin"
)

// searchCfg 注册申请搜索配置：可搜索字段、可排序字段、标签（状态/用户类型/学校）与返回列。
// Columns 不含 password（密码哈希），不读取也不对外返回。
var searchCfg = searchsvc.SearchConfig{
	Table:             "register_requests",
	Item:              "注册请求",
	Columns:           []string{"id", "username", "nickname", "type", "student_num", "real_name", "school", "created_at", "status", "created_user_id", "reviewer_user_id", "review_comment", "reviewed_at"},
	Fields:            []searchsvc.Field{{ID: "id", Column: "id", Numeric: true}, {ID: "student_num", Column: "student_num"}, {ID: "real_name", Column: "real_name"}, {ID: "created_user_id", Column: "created_user_id", Numeric: true}},
	MatchMethods:      searchsvc.MatchMethodValues(),
	SortableFields:    []searchsvc.Field{{ID: "created_at", Column: "created_at"}, {ID: "reviewed_at", Column: "reviewed_at"}},
	Tags:              []searchsvc.Tag{{ID: "status", Column: "status", ValueMap: searchsvc.ValueMapOf(model.RegisterRequestStatusNames())}, {ID: "type", Column: "type", ValueMap: searchsvc.ValueMapOf(model.UserTypeNames())}, {ID: "school", Column: "school", ValueMap: searchsvc.ValueMapOf(model.SchoolNames())}},
	DefaultSortColumn: "id",
}

// searchInfo 注册申请搜索能力的静态描述，供前端渲染搜索表单。
var searchInfo = searchsvc.GetInfo(&searchCfg)

// SearchInfoHandler 返回注册申请搜索的字段、匹配方法、可排序字段与标签取值；需要 register_requests.list 权限。
func SearchInfoHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)
	if !permsvc.HasPermission(claims, permsvc.PermRegisterRequestList) {
		return errs.PermissionDeniedError().AppendDetails("权限不足").Seal()
	}
	c.JSON(http.StatusOK, searchInfo)
	return nil
}

// SearchQueryHandler 执行注册申请搜索，返回总数与申请摘要（不含密码哈希）；需要 register_requests.list 权限。
func SearchQueryHandler(c *gin.Context) *errs.Error {
	var req searchsvc.SearchRequest
	if err := handling.BindJSON(c, &req); err != nil {
		return err
	}

	claims := handling.MustGetClaims(c)
	if !permsvc.HasPermission(claims, permsvc.PermRegisterRequestList) {
		return errs.PermissionDeniedError().AppendDetails("权限不足").Seal()
	}

	requests, err := searchsvc.ExecSearch[model.RegisterRequest](c.Request.Context(), &searchCfg, &req)
	if err != nil {
		return err
	}

	data := make([]gin.H, 0, len(requests.Data))
	for _, request := range requests.Data {
		data = append(data, handling.RegisterRequestJSON(request))
	}

	handling.RespondList(c, requests.Count, data)
	return nil
}
