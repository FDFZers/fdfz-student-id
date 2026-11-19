package auth

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/middleware"
	captchasvc "fdfz-student-id/internal/service/captcha"
	"fdfz-student-id/internal/util/crypto"
	"fdfz-student-id/internal/util/handling"
	"net/http"

	"github.com/gin-gonic/gin"
)

// InitRoutes 注册认证相关路由：公开的 JWKS 与 Altcha Challenge 挂在 api 组，
// 注册、登录、刷新、登出、密码重置、验证与提权等敏感操作挂在 internal 组。
// 每个处理器都经 handling.Wrap 统一追加端点级失败文案。
func InitRoutes(api, internal *gin.RouterGroup) {
	a := api.Group("/auth")
	i := internal.Group("/auth")

	i.POST("/register", middleware.LimitSize(5<<20), handling.Wrap("注册失败", createRegisterHandler))
	i.POST("/login/init", handling.Wrap("登录失败", loginInitHandler))
	i.POST("/login/finalize", handling.Wrap("登录失败", loginFinalizeHandler))
	i.POST("/refresh", handling.Wrap("令牌刷新失败", refreshTokenHandler))
	// 本站前端用 Bearer 取权限串与应用列表（令牌内只存权限 ID）。
	i.GET("/claims", middleware.RequireToken(), handling.Wrap("令牌声明获取失败", claimsHandler))
	i.POST("/logout", middleware.RequireToken(), handling.Wrap("登出失败", logoutHandler))

	i.POST("/password_reset/init/email", handling.Wrap("密码重置初始化失败", resetPasswordEmailInitHandler))
	i.POST("/password_reset/init/qq", handling.Wrap("密码重置初始化失败", resetPasswordQQInitHandler))
	i.POST("/password_reset/finalize", handling.Wrap("密码重置失败", resetPasswordFinalizeHandler))

	i.POST("/verify/email/init", handling.Wrap("邮箱验证码发送失败", verifyEmailInitHandler))
	i.POST("/verify/email/verify", handling.Wrap("邮箱验证失败", verifyEmailHandler))
	i.POST("/verify/qq/init", handling.Wrap("QQ 验证码初始化失败", verifyQQInitHandler))
	i.POST("/verify/qq/verify", handling.Wrap("QQ 验证失败", verifyQQHandler))
	i.POST("/verify/totp", handling.Wrap("TOTP 验证失败", verifyTOTPHandler))

	// 提权接口要求已登录（有效访问令牌），是否具备提权令牌由各业务接口另行校验。
	i.POST("/stepup/init", middleware.RequireToken(), handling.Wrap("二次验证初始化失败", stepupInitHandler))
	i.POST("/stepup/finalize", middleware.RequireToken(), handling.Wrap("二次验证失败", stepupFinalizeHandler))

	// 令牌声明（OAuth 客户端用 Bearer 取权限）；JWKS 供其他服务离线校验本服务签发的 JWT。
	a.GET("/claims", middleware.RequireToken(), handling.Wrap("令牌声明获取失败", claimsHandler))
	a.GET("/jwks", func(c *gin.Context) {
		c.Header("Content-Type", "application/json")
		c.String(http.StatusOK, crypto.JWKS)
	})
	a.GET("/challenge", handling.Wrap("Altcha Challenge 生成失败", challengeHandler))
}

// challengeHandler 生成 Altcha 人机验证 Challenge，供前端完成工作量证明后随表单回传。
func challengeHandler(c *gin.Context) *errs.Error {
	challenge, err := captchasvc.CreateChallenge()
	if err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to create altcha challenge")
	}
	c.JSON(http.StatusOK, challenge)
	return nil
}
