package app

import (
	"net/http"

	"fdfz-student-id/internal/errs"
	oauthsvc "fdfz-student-id/internal/service/oauth"
	permsvc "fdfz-student-id/internal/service/perm"
	"fdfz-student-id/internal/util/handling"

	"github.com/gin-gonic/gin"
)

// listAuthorizationsHandler 查看授权记录：查自己需 oauth.read，查他人需 oauths.read。
func listAuthorizationsHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)
	targetID, err := handling.ParseUserID(c, claims.UserID, "id")
	if err != nil {
		return err
	}

	var allowed bool
	if targetID == claims.UserID {
		allowed = permsvc.HasPermission(claims, permsvc.PermOAuthRead)
	} else {
		allowed = permsvc.HasPermission(claims, permsvc.PermOAuthsRead)
	}
	if !allowed {
		return errs.PermissionDeniedError().AppendDetails("权限不足", "鉴权失败").Seal()
	}

	if err := handling.EnsureUserExists(c, targetID); err != nil {
		return err
	}

	authorizations, err := oauthsvc.ListUserAuthorizations(c.Request.Context(), targetID)
	if err != nil {
		return err
	}

	c.JSON(http.StatusOK, gin.H{"authorizations": authorizations})
	return nil
}

// revokeAuthorizationHandler 撤销授权记录：撤销自己的需 oauth.revoke，撤销他人的需 oauths.revoke。
func revokeAuthorizationHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)

	authorizationID, err := handling.ParseID(c, "authID", "授权记录")
	if err != nil {
		return err
	}

	authorization, err := oauthsvc.GetAuthorizationByID(c.Request.Context(), authorizationID)
	if err != nil {
		return err
	}
	if authorization == nil {
		return errs.NotFoundError().AppendDetails("授权记录不存在")
	}

	var allowed bool
	if authorization.UserID == claims.UserID {
		allowed = permsvc.HasPermission(claims, permsvc.PermOAuthRevoke)
	} else {
		allowed = permsvc.HasPermission(claims, permsvc.PermOAuthsRevoke)
	}
	if !allowed {
		return errs.PermissionDeniedError().AppendDetails("权限不足", "鉴权失败").Seal()
	}

	if err := oauthsvc.DeleteAuthorization(c.Request.Context(), authorizationID); err != nil {
		return err
	}

	handling.RespondOK(c)
	return nil
}
