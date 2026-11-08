package permissions

import (
	"net/http"

	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/service/perm"

	"github.com/gin-gonic/gin"
)

// getReloadStatusHandler 返回权限目录重载状态，不触发重载。
func getReloadStatusHandler(c *gin.Context) *errs.Error {
	c.JSON(http.StatusOK, perm.GetReloadStatus())
	return nil
}

// reloadHandler 同步触发一次权限目录重载并返回最新状态；失败时返回加载错误（由 Wrap 追加端点文案）。
func reloadHandler(c *gin.Context) *errs.Error {
	if err := perm.ReloadNow(c.Request.Context()); err != nil {
		return err
	}

	c.JSON(http.StatusOK, perm.GetReloadStatus())
	return nil
}
