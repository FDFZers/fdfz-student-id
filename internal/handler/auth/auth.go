package auth

import (
	"fdfz-student-id/internal/middleware"

	"github.com/gin-gonic/gin"
)

func InitRoutes(internal *gin.RouterGroup) {
	group := internal.Group("/auth")
	group.POST("/register", middleware.LimitSize(5<<20), createRegisterHandler)
	group.POST("/login/init", loginInitHandler)
	group.POST("/login/finalize", loginFinalizeHandler)
	group.POST("/verify/email/init", verifyEmailInitHandler)
	group.POST("/verify/email/verify", verifyEmailHandler)
	group.POST("/verify/totp", verifyTOTPHandler)
	group.POST("/refresh", refreshTokenHandler)
}
