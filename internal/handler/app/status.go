package app

import (
	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	appsvc "fdfz-student-id/internal/service/app"
	"fdfz-student-id/internal/util/handling"

	"github.com/gin-gonic/gin"
)

// setAppStatus 管理员停用/启用应用：核心应用不允许停用，状态未变化时直接返回当前记录。
func setAppStatus(c *gin.Context, status model.AppStatus) *errs.Error {
	a, err := handling.ResolveApp(c)
	if err != nil {
		return err
	}

	if status == model.AppStatusSuspended && a.Namespace == appsvc.CoreNamespace {
		return errs.IllegalStateError().AppendDetails("核心应用不允许停用").Seal()
	}
	if a.Status == status {
		respondApp(c, a)
		return nil
	}

	updated, err := appsvc.SetAppStatus(c.Request.Context(), db.R, a.ID, status)
	if err != nil {
		return err
	}

	respondApp(c, updated)
	return nil
}

// suspendAppHandler 管理员停用应用；停用后应用立即退出权限目录并删除全部刷新令牌。
func suspendAppHandler(c *gin.Context) *errs.Error {
	return setAppStatus(c, model.AppStatusSuspended)
}

// activateAppHandler 管理员启用应用，应用重新进入权限目录。
func activateAppHandler(c *gin.Context) *errs.Error {
	return setAppStatus(c, model.AppStatusActive)
}
