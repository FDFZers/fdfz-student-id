package notification

import (
	"net/http"

	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	searchsvc "fdfz-student-id/internal/service/search"
	"fdfz-student-id/internal/util/handling"

	"github.com/gin-gonic/gin"
)

// notificationSearchCfg 是站内通知的管理端搜索配置；来源与接收人字段来自 JOIN，数值 ID 用 exact 精确过滤。
var notificationSearchCfg = searchsvc.SearchConfig{
	Table: `notifications n
		JOIN users u ON u.id = n.user_id
		LEFT JOIN apps a ON a.id = n.app_id
		LEFT JOIN users su ON su.id = n.sender_user_id`,
	Item: "站内通知",
	Columns: []string{
		"n.id",
		"n.user_id",
		"u.username AS recipient_username",
		"u.nickname AS recipient_nickname",
		"n.app_id",
		"COALESCE(a.name, '') AS app_name",
		"COALESCE(a.namespace, '') AS app_namespace",
		"n.sender_user_id",
		"COALESCE(su.username, '') AS sender_username",
		"su.nickname AS sender_nickname",
		"n.icon",
		"n.title",
		"n.content",
		"n.ext",
		"n.read_at",
		"n.created_at",
	},
	Fields: []searchsvc.Field{
		{ID: "id", Column: "n.id", Numeric: true},
		{ID: "user_id", Column: "n.user_id", Numeric: true},
		{ID: "app_id", Column: "n.app_id", Numeric: true},
		{ID: "sender_user_id", Column: "n.sender_user_id", Numeric: true},
		{ID: "title", Column: "n.title"},
		{ID: "content", Column: "n.content"},
		{ID: "recipient_username", Column: "u.username"},
		{ID: "recipient_nickname", Column: "u.nickname"},
		{ID: "sender_username", Column: "su.username"},
		{ID: "sender_nickname", Column: "su.nickname"},
		{ID: "app_name", Column: "a.name"},
		{ID: "app_namespace", Column: "a.namespace"},
	},
	MatchMethods: searchsvc.MatchMethodValues(),
	SortableFields: []searchsvc.Field{
		{ID: "id", Column: "n.id"},
		{ID: "created_at", Column: "n.created_at"},
		{ID: "read_at", Column: "n.read_at"},
		{ID: "title", Column: "n.title"},
	},
	Tags: []searchsvc.Tag{
		{ID: "read", Column: "(n.read_at IS NOT NULL)", ValueMap: map[string]string{"true": "read", "false": "unread"}},
		{ID: "source", Column: "(n.app_id IS NOT NULL)", ValueMap: map[string]string{"true": "app", "false": "admin"}},
	},
	DefaultSortColumn: "n.created_at DESC, n.id DESC",
}

func notificationSearchInfoHandler(c *gin.Context) *errs.Error {
	c.JSON(http.StatusOK, searchsvc.GetInfo(&notificationSearchCfg))
	return nil
}

// notificationSearchQueryHandler 查询全部用户的站内通知，需要 notifications.read 权限。
func notificationSearchQueryHandler(c *gin.Context) *errs.Error {
	var req searchsvc.SearchRequest
	if err := handling.BindJSON(c, &req); err != nil {
		return err
	}

	result, err := searchsvc.ExecSearch[model.Notification](c.Request.Context(), &notificationSearchCfg, &req)
	if err != nil {
		return err
	}

	handling.RespondList(c, result.Count, result.Data)
	return nil
}
