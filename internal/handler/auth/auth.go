package auth

import (
	"fdfz-student-id/internal/middleware"

	"github.com/gin-gonic/gin"
)

func InitRoutes(internal *gin.RouterGroup) {
	group := internal.Group("/auth")
	group.POST("/register", middleware.LimitSize(5<<20), createRegisterRequestHandler)
	group.POST("/login/init", loginInitRequestHandler)
	group.POST("/login/finalize", loginFinalizeRequestHandler)
	group.POST("/verify/email/init", verifyEmailInit)
	group.POST("/verify/email/verify", verifyEmail)
	group.POST("/verify/totp", verifyTOTP)
}
