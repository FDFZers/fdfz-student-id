package middleware

import (
	"errors"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/util/crypto"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func ParseToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		token, found := strings.CutPrefix(header, "Bearer ")
		if !found {
			token, _ = c.Cookie("access_token")
		}
		if token == "" {
			c.Next()
			return
		}

		claims, err := crypto.ParseJWT(token)
		if err != nil {
			if errors.Is(err, jwt.ErrTokenExpired) {
				errs.TokenExpiredError().AppendDetails("令牌过期", "鉴权失败").Abort(c)
				return
			}
			errs.InvalidTokenError().AppendDetails("无效的令牌", "鉴权失败").Abort(c)
			return
		}
		c.Set("token_claims", claims)
	}
}

func RequireToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		ParseToken()(c)
		if _, exists := c.Get("token_claims"); !exists {
			errs.InvalidTokenError().AppendDetails("未提供令牌", "鉴权失败").Abort(c)
			return
		}
		c.Next()
	}
}

func RequireTokenType(typ model.TokenType) gin.HandlerFunc {
	return func(c *gin.Context) {
		RequireToken()(c)
		if c.IsAborted() {
			return
		}

		claims, ok := c.MustGet("token_claims").(*model.RegisteredTokenClaims)
		if !ok {
			errs.InvalidTokenError().AppendDetails("无效的令牌", "鉴权失败").Abort(c)
			return
		}
		if claims.TokenType != typ {
			errs.InvalidTokenError().AppendDetails("令牌类型错误", "鉴权失败").Abort(c)
			return
		}
		c.Next()
	}
}

func RequireStepupToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := c.Cookie("stepup_token")
		if token == "" || errors.Is(err, http.ErrNoCookie) {
			errs.TokenExpiredError().AppendDetails("未提供提权令牌", "鉴权失败").Abort(c)
			return
		} else if err != nil {
			errs.InvalidTokenError().AppendDetails("无效的提权令牌", "鉴权失败").Abort(c)
		}

		claims, err := crypto.ParseJWT(token)
		if err != nil {
			if errors.Is(err, jwt.ErrTokenExpired) {
				errs.TokenExpiredError().AppendDetails("提权令牌过期", "鉴权失败").Abort(c)
				return
			}
			errs.InvalidTokenError().AppendDetails("无效的提权令牌", "鉴权失败").Abort(c)
			return
		}
		if claims.TokenType != model.TokenTypeStepup {
			errs.InvalidTokenError().AppendDetails("令牌类型错误", "鉴权失败").Abort(c)
			return
		}
		c.Set("token_claims", claims)
		c.Next()
	}
}
