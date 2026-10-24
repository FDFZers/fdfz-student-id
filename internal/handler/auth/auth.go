package auth

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/middleware"
	"fdfz-student-id/internal/service/captcha"
	"fdfz-student-id/internal/util/crypto"
	"net/http"

	"github.com/gin-gonic/gin"
)

func InitRoutes(api, internal *gin.RouterGroup) {
	a := api.Group("/auth")
	i := internal.Group("/auth")
	i.POST("/register", middleware.LimitSize(5<<20), createRegisterHandler)
	i.POST("/login/init", loginInitHandler)
	i.POST("/login/finalize", loginFinalizeHandler)
	i.POST("/verify/email/init", verifyEmailInitHandler)
	i.POST("/verify/email/verify", verifyEmailHandler)
	i.POST("/verify/totp", verifyTOTPHandler)
	i.POST("/refresh", refreshTokenHandler)
	i.POST("/logout", logoutHandler)
	a.GET("/jwks", func(c *gin.Context) {
		c.Header("Content-Type", "application/json")
		c.String(http.StatusOK, crypto.JWKS)
	})
	a.GET("/challenge", func(c *gin.Context) {
		challenge, err := captcha.CreateChallenge()
		if err != nil {
			errs.CreateAndLogInternalError(err, "Failed to create altcha challenge").AppendDetails("Altcha Challenge 生成失败")
			return
		}
		c.JSON(http.StatusOK, challenge)
	})
}
