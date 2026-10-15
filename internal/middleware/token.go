package middleware

import (
	"errors"
	"fdfz-student-id/internal/crypto"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func ParseToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		token, found := strings.CutPrefix(header, "Bearer ")
		if !found {
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
		c.Next()
	}
}

func RequireToken() gin.HandlerFunc {
	return func(c *gin.Context) {
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
		claims := c.MustGet("token_claims").(*model.TokenClaims)
		if claims.TokenType != typ {
			errs.InvalidTokenError().AppendDetails("令牌类型错误", "鉴权失败").Abort(c)
			return
		}
		c.Next()
	}
}
