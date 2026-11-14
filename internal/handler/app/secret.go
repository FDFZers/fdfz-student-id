package app

import (
	"fdfz-student-id/internal/errs"
	appsvc "fdfz-student-id/internal/service/app"
	"net/http"

	"github.com/gin-gonic/gin"
)

// rotateSecretHandler 重置 confidential 客户端密钥，新密钥明文仅返回一次。
// 管理员与应用所有者（需 app.update）均可操作。
func rotateSecretHandler(c *gin.Context) *errs.Error {
	a, err := managedApp(c, true)
	if err != nil {
		return err
	}
	if !a.ClientType.IsConfidential() {
		return errs.IllegalStateError().AppendDetails("公开客户端不支持客户端密钥").Seal()
	}

	secret, err := appsvc.RotateAppSecret(c.Request.Context(), a.ID)
	if err != nil {
		return err
	}

	c.JSON(http.StatusOK, gin.H{
		"client_secret": secret,
	})
	return nil
}
