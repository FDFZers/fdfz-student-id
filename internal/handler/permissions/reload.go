package permissions

import (
	"net/http"

	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/service/perm"

	"github.com/gin-gonic/gin"
)

func getReloadStatusHandler(c *gin.Context) *errs.Error {
	c.JSON(http.StatusOK, perm.GetReloadStatus())
	return nil
}

func reloadHandler(c *gin.Context) *errs.Error {
	if err := perm.ReloadNow(c.Request.Context()); err != nil {
		return err
	}

	c.JSON(http.StatusOK, perm.GetReloadStatus())
	return nil
}
