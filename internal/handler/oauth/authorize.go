package oauth

import (
	"net/http"

	"fdfz-student-id/internal/errs"
	notificationsvc "fdfz-student-id/internal/service/notifications"
	oauthsvc "fdfz-student-id/internal/service/oauth"
	"fdfz-student-id/internal/util/handling"

	"github.com/gin-gonic/gin"
)

// authorizePreviewHandler 校验授权请求并返回确认页所需的详情；权限固定取自应用登记值。
func authorizePreviewHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)

	preview, err := oauthsvc.PreviewAuthorization(c.Request.Context(), claims.UserID, oauthsvc.AuthorizationParams{
		ClientID:      c.Query("client_id"),
		RedirectURI:   c.Query("redirect_uri"),
		State:         c.Query("state"),
		CodeChallenge: c.Query("code_challenge"),
	})
	if err != nil {
		return err
	}

	c.JSON(http.StatusOK, preview)
	return nil
}

// authorizeDecisionRequest 提交授权决策；授予应用登记的全部可授予权限。
type authorizeDecisionRequest struct {
	RequestID          string `json:"request_id"`
	Approve            *bool  `json:"approve"`
	AllowNotifications *bool  `json:"allow_notifications"` // 可选，缺省沿用预览页的默认值
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

	result, err := oauthsvc.ApproveAuthorization(
		c.Request.Context(), claims.UserID, req.RequestID, *req.Approve, req.AllowNotifications,
	)
	if err != nil {
		return err
	}

	if result.Approved && result.App != nil {
		notificationsvc.ToUser(c.Request.Context(), claims.UserID, notificationsvc.NewOAuthAuthorizedMessage(
			result.App.Name, result.Permissions, result.AllowNotifications,
		))
	}

	c.JSON(http.StatusOK, gin.H{"redirect_to": result.RedirectTo})
	return nil
}
