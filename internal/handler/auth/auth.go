package auth

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/middleware"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/service/captcha"
	"fdfz-student-id/internal/util/crypto"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

func InitRoutes(api, internal *gin.RouterGroup) {
	a := api.Group("/auth")
	i := internal.Group("/auth")

	i.POST("/register", createRegisterHandler)
	i.POST("/login/init", loginInitHandler)
	i.POST("/login/finalize", loginFinalizeHandler)
	i.POST("/verify/email/init", verifyEmailInitHandler)
	i.POST("/verify/email/verify", verifyEmailHandler)
	i.POST("/verify/qq/init", verifyQQInitHandler)
	i.POST("/verify/qq/verify", verifyQQHandler)
	i.POST("/verify/totp", verifyTOTPHandler)
	i.POST("/password_reset/init/email", resetPasswordEmailInitHandler)
	i.POST("/password_reset/init/qq", resetPasswordQQInitHandler)
	i.POST("/password_reset/finalize", resetPasswordFinalizeHandler)
	i.POST("/stepup/init", middleware.RequireTokenType(model.TokenTypeUser), stepupInitHandler)
	i.POST("/stepup/finalize", middleware.RequireTokenType(model.TokenTypeUser), stepupFinalizeHandler)
	i.POST("/refresh", refreshTokenHandler)
	i.POST("/logout", middleware.RequireTokenType(model.TokenTypeUser), logoutHandler)

	a.GET("/jwks", func(c *gin.Context) {
		c.Header("Content-Type", "application/json")
		c.String(http.StatusOK, crypto.JWKS)
	})
	a.GET("/challenge", func(c *gin.Context) {
		challenge, err := captcha.CreateChallenge()
		if err != nil {
			errs.CreateAndLogInternalError(err, "Failed to create altcha challenge").AppendDetails("Altcha Challenge 生成失败").Respond(c)
			return
		}
		c.JSON(http.StatusOK, challenge)
	})
}

func respondBanned(c *gin.Context, ban *model.UserBan, item string) {
	if ban.EndTime.Valid {
		errs.PermissionDeniedError().AppendDetails(
			fmt.Sprintf("用户已封禁：%s（%s）", ban.Reason, ban.EndTime.Time.Format("2006-01-02 15:04:05")),
			item,
		).Respond(c)
	} else {
		errs.PermissionDeniedError().AppendDetails(
			fmt.Sprintf("用户已永久封禁：%s", ban.Reason),
			item,
		).Respond(c)
	}
}
