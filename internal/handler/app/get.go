package app

import (
	"fdfz-student-id/internal/errs"

	"github.com/gin-gonic/gin"
)

// getAppHandler 获取应用详情：管理员可读取全部应用，应用所有者可读取自己的应用（含已停用应用）。
func getAppHandler(c *gin.Context) *errs.Error {
	a, err := managedApp(c, false)
	if err != nil {
		return err
	}

	respondApp(c, a)
	return nil
}
