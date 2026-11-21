package app

import (
	"fdfz-student-id/internal/errs"
	appsvc "fdfz-student-id/internal/service/app"
	"fdfz-student-id/internal/util/handling"
	"net/http"

	"github.com/gin-gonic/gin"
)

// rotateSecretHandler 重置客户端密钥，新密钥明文仅返回一次。
// confidential 与设备流客户端均可持有密钥；管理员与应用所有者（需 app.update）均可操作。
func rotateSecretHandler(c *gin.Context) *errs.Error {
	a, err := managedApp(c, true)
	if err != nil {
		return err
	}
	if !a.ClientType.SupportsSecret() {
		return errs.IllegalStateError().AppendDetails("该客户端类型不支持客户端密钥").Seal()
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

// deleteSecretHandler 删除客户端密钥；删除后应用无法再用密钥认证或发送通知。
// 管理员与应用所有者（需 app.update）均可操作，重复删除视为成功。
func deleteSecretHandler(c *gin.Context) *errs.Error {
	a, err := managedApp(c, true)
	if err != nil {
		return err
	}
	if !a.ClientType.SupportsSecret() {
		return errs.IllegalStateError().AppendDetails("该客户端类型不支持客户端密钥").Seal()
	}

	if err := appsvc.DeleteAppSecret(c.Request.Context(), a.ID); err != nil {
		return err
	}

	handling.RespondOK(c)
	return nil
}
