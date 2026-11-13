package app

import (
	"fdfz-student-id/internal/errs"
	appsvc "fdfz-student-id/internal/service/app"
	"fdfz-student-id/internal/service/filestore"
	"fdfz-student-id/internal/service/perm"
	"fdfz-student-id/internal/util/handling"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
)

// deleteAppHandler 删除应用：全局 apps.delete 可删除任意应用，应用所有者可凭 app.delete
// 删除自己的应用。软删除记录并清理用户授权与刷新令牌；图标在事务成功后尽力清理。
func deleteAppHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)
	a, err := handling.ResolveApp(c)
	if err != nil {
		return err
	}

	isGlobal := perm.HasPermission(claims, perm.PermAppsDelete)
	isOwner := a.OwnerUserID == claims.UserID && perm.HasPermission(claims, perm.PermAppDelete)
	if !isGlobal && !isOwner {
		return errs.PermissionDeniedError().AppendDetails("权限不足").Seal()
	}
	if a.Namespace == appsvc.CoreNamespace {
		return errs.IllegalStateError().AppendDetails("核心应用不允许删除").Seal()
	}

	deleted, err := appsvc.DeleteApp(c.Request.Context(), a.ID)
	if err != nil {
		return err
	}

	// 图标文件按应用 ID 固定存放；删除应用后尽力清理，失败只记录日志
	if e := filestore.DeleteFile(appIconSlug(deleted.ID)); e != nil && e.HTTPCode != http.StatusNotFound {
		slog.Warn("Failed to delete app icon file",
			"app_id", deleted.ID, "slug", appIconSlug(deleted.ID), "error", e.Info.Error)
	}

	c.JSON(http.StatusOK, gin.H{})
	return nil
}
