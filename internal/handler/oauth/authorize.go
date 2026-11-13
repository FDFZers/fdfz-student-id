package oauth

import (
	"net/http"
	"strings"

	"fdfz-student-id/internal/errs"
	oauthsvc "fdfz-student-id/internal/service/oauth"
	"fdfz-student-id/internal/util/handling"

	"github.com/gin-gonic/gin"
)

// authorizePreviewHandler 校验授权请求并返回确认页所需的详情。
// 前端拿到 request_id 后展示应用信息与权限列表，再调用 POST /oauth/authorize 完成授权。
func authorizePreviewHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)

	preview, err := oauthsvc.PreviewAuthorization(c.Request.Context(), claims.UserID, oauthsvc.AuthorizationParams{
		ClientID:      c.Query("client_id"),
		RedirectURI:   c.Query("redirect_uri"),
		Permission:    strings.Join(c.QueryArray("permission"), " "),
		State:         c.Query("state"),
		CodeChallenge: c.Query("code_challenge"),
	})
	if err != nil {
		return err
	}

	c.JSON(http.StatusOK, preview)
	return nil
}

// authorizeDecisionRequest 是授权确认页的提交体。
// permissions 为 nil 表示授予全部可授予权限；为空数组表示一项都不授予。
type authorizeDecisionRequest struct {
	RequestID   string    `json:"request_id"`
	Approve     *bool     `json:"approve"`
	Permissions *[]string `json:"permissions"`
}

// authorizeDecisionHandler 处理用户的同意/拒绝操作，返回客户端回调地址。
func authorizeDecisionHandler(c *gin.Context) *errs.Error {
	var req authorizeDecisionRequest
	if err := handling.BindJSON(c, &req); err != nil {
		return err
	}
	if req.RequestID == "" {
		return errs.BadRequestError().AppendDetails("缺少授权请求 ID")
	}
	if req.Approve == nil {
		return errs.BadRequestError().AppendDetails("缺少授权决定")
	}

	claims := handling.MustGetClaims(c)
	var permissions []string
	if req.Permissions != nil {
		permissions = *req.Permissions
	}

	redirectTo, err := oauthsvc.ApproveAuthorization(
		c.Request.Context(), claims.UserID, req.RequestID, *req.Approve, permissions,
	)
	if err != nil {
		return err
	}

	c.JSON(http.StatusOK, gin.H{"redirect_to": redirectTo})
	return nil
}
