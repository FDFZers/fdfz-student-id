package middleware

import (
	"fdfz-student-id/internal/crypto"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/perm"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"
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
			errs.UnauthorizedError().AppendDetails("令牌解析失败", "鉴权失败").Abort(c)
			return
		}
		c.Set("token_claims", claims)
		c.Next()
	}
}

func RequireToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		if _, exists := c.Get("token_claims"); !exists {
			errs.UnauthorizedError().AppendDetails("未提供令牌", "鉴权失败").Abort(c)
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
			errs.UnauthorizedError().AppendDetails("令牌类型错误", "鉴权失败").Abort(c)
			return
		}
		c.Next()
	}
}

func RequirePermission(matchable perm.MatchFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		RequireToken()(c)
		claims := c.MustGet("token_claims").(*model.TokenClaims)
		if slices.ContainsFunc(claims.Permissions, matchable) {
			c.Next()
			return
		}
		errs.UnauthorizedError().AppendDetails("权限不足", "鉴权失败").Abort(c)
	}
}
