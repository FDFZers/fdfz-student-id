package middleware

import (
	"errors"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/util/crypto"
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
			}
			errs.InvalidTokenError().AppendDetails("无效的令牌", "鉴权失败").Abort(c)
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
