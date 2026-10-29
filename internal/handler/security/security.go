package security

import (
	"github.com/gin-gonic/gin"
)

const (
	bindEmailAttemptsKind = "email"
	bindTOTPAttemptsKind  = "totp"
)

func InitRoutes(internal *gin.RouterGroup) {
	group := internal.Group("/user/security")

	group.POST("/email/init", bindingValidateClaims(), emailBindInitHandler)
	group.POST("/email/verify", bindingValidateClaims(), emailBindVerifyHandler)
	group.DELETE("/email", bindingValidateClaims(), emailUnbindHandler)
	group.POST("/totp/init", bindingValidateClaims(), totpBindInitHandler)
	group.POST("/totp/verify", bindingValidateClaims(), totpBindVerifyHandler)
	group.DELETE("/totp", bindingValidateClaims(), totpUnbindHandler)
}
