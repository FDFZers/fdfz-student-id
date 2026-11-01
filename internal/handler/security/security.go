package security

import (
	"fdfz-student-id/internal/middleware"

	"github.com/gin-gonic/gin"
)

const (
	bindEmailAttemptsKind = "email"
	bindTOTPAttemptsKind  = "totp"
	bindQQAttemptsKind    = "qq"
)

func InitRoutes(internal *gin.RouterGroup) {
	group := internal.Group("/user/security")

	group.POST("/email/init", bindingValidateClaims(), emailBindInitHandler)
	group.POST("/email/verify", bindingValidateClaims(), emailBindVerifyHandler)
	group.DELETE("/email", bindingValidateClaims(), emailUnbindHandler)
	group.POST("/totp/init", bindingValidateClaims(), totpBindInitHandler)
	group.POST("/totp/verify", bindingValidateClaims(), totpBindVerifyHandler)
	group.DELETE("/totp", bindingValidateClaims(), totpUnbindHandler)
	group.POST("/qq/init", bindingValidateClaims(), qqBindInitHandler)
	group.POST("/qq/verify", bindingValidateClaims(), qqBindVerifyHandler)
	group.DELETE("/qq", bindingValidateClaims(), qqUnbindHandler)

	group.POST("/password/change", middleware.RequireStepupToken(), changePasswordHandler)
	group.GET("/sessions", middleware.RequireToken(), listSessionsHandler)
	group.DELETE("/sessions", middleware.RequireStepupToken(), revokeAllSessionsHandler)
	group.DELETE("/sessions/:id", middleware.RequireStepupToken(), revokeSessionHandler)
}
