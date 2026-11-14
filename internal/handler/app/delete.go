package app

import (
	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
	appsvc "fdfz-student-id/internal/service/app"
	filestoresvc "fdfz-student-id/internal/service/filestore"
	permsvc "fdfz-student-id/internal/service/perm"
	"fdfz-student-id/internal/util/handling"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
)

// deleteAppHandler 删除应用：全局 apps.delete 可删除任意应用，应用所有者凭 app.delete 删除自己的应用。
func deleteAppHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)
	a, err := handling.ResolveApp(c)
	if err != nil {
		return err
	}

	isGlobal := permsvc.HasPermission(claims, permsvc.PermAppsDelete)
	isOwner := a.OwnerUserID == claims.UserID && permsvc.HasPermission(claims, permsvc.PermAppDelete)
	if !isGlobal && !isOwner {
		return errs.PermissionDeniedError().AppendDetails("权限不足").Seal()
	}
	if a.Namespace == appsvc.CoreNamespace {
		return errs.IllegalStateError().AppendDetails("核心应用不允许删除").Seal()
	}

	deleted, err := appsvc.DeleteApp(c.Request.Context(), db.R, a.ID)
	if err != nil {
		return err
	}

	if err := filestoresvc.DeleteFile(appIconSlug(deleted.ID)); err != nil && err.HTTPCode != http.StatusNotFound {
		slog.Warn("Failed to delete app icon file",
			"app_id", deleted.ID, "slug", appIconSlug(deleted.ID), "error", err.Info.Error)
	}

	handling.RespondOK(c)
	return nil
}
