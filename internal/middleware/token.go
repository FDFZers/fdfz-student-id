package middleware

import (
	"errors"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/service/auth"
	"fdfz-student-id/internal/service/perm"
	"fdfz-student-id/internal/util/crypto"
	"fdfz-student-id/internal/util/handling"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func ParseToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		token, found := strings.CutPrefix(header, "Bearer ")
		if !found {
			token, _ = c.Cookie("access_token")
		}
		if token == "" {
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
		if c.IsAborted() {
			return
		}
		if _, exists := c.Get("token_claims"); !exists {
			errs.InvalidTokenError().AppendDetails("未提供令牌", "鉴权失败").Abort(c)
			return
		}
	}
}

func RequirePermission(permissions ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		RequireToken()(c)
		if c.IsAborted() {
			return
		}
		for _, permission := range permissions {
			if !perm.HasPermission(handling.MustGetClaims(c), permission) {
				errs.PermissionDeniedError().AppendDetails("权限不足", "鉴权失败").Abort(c)
				return
			}
		}
	}
}

func ValidateStepupToken(c *gin.Context) *errs.Error {
	token, e := c.Cookie("stepup_token")
	if token == "" || errors.Is(e, http.ErrNoCookie) {
		return errs.TokenExpiredError().AppendDetails("未提供提权令牌", "鉴权失败")
	} else if e != nil {
		return errs.InvalidTokenError().AppendDetails("无效的提权令牌", "鉴权失败")
	}

	claims, e := crypto.ParseJWT(token)
	if e != nil {
		if errors.Is(e, jwt.ErrTokenExpired) {
			return errs.TokenExpiredError().AppendDetails("提权令牌过期", "鉴权失败")
		}
		return errs.InvalidTokenError().AppendDetails("无效的提权令牌", "鉴权失败")
	}
	if claims.TokenType != model.TokenTypeStepup {
		return errs.InvalidTokenError().AppendDetails("令牌类型错误", "鉴权失败")
	}

	if !claims.SessionID.Valid {
		return errs.InvalidTokenError().AppendDetails("无效的会话", "鉴权失败")
	}
	sessionID, e := uuid.Parse(claims.SessionID.String)
	if e != nil {
		return errs.InvalidTokenError().AppendDetails("无效的会话", "鉴权失败")
	}
	session, err := auth.GetSessionByUUID(c.Request.Context(), sessionID)
	if err != nil {
		if err.Info.Error == "not_found" {
			return errs.InvalidTokenError().AppendDetails("会话不存在", "鉴权失败")
		}
		return err.AppendDetails("鉴权失败")
	}
	if session == nil || session.UserID != claims.UserID ||
		session.RevokedAt != nil || !time.Now().Before(session.ExpiresAt) {
		return errs.InvalidTokenError().AppendDetails("无效的会话", "鉴权失败")
	}

	revokedAt, revokedErr := auth.GetStepupRevokedAt(c.Request.Context(), claims.UserID)
	if revokedErr != nil {
		return revokedErr
	} else if !revokedAt.IsZero() && claims.IssuedAt != nil && !claims.IssuedAt.Time.After(revokedAt) {
		return errs.InvalidTokenError().AppendDetails("提权令牌已失效", "鉴权失败")
	}

	c.Set("token_claims", claims)
	return nil
}

func RequireStepupToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := ValidateStepupToken(c); err != nil {
			err.Abort(c)
			return
		}
	}
}

func RequireAppAccess(appParam string, globalPermission string, ownedAppPermission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		RequireToken()(c)
		if c.IsAborted() {
			return
		}

		claims := handling.GetClaimsOrNil(c)
		if claims.TokenType != model.TokenTypeUser {
			errs.InvalidTokenError().AppendDetails("令牌类型错误", "鉴权失败").Abort(c)
			return
		}

		if perm.HasPermission(claims, globalPermission) {
			c.Set("app_access_scope", "global")
			return
		}

		appID, err := strconv.ParseInt(c.Param(appParam), 10, 64)
		if err != nil || appID <= 0 {
			errs.BadRequestError().AppendDetails("无效的应用 ID", "鉴权失败").Abort(c)
			return
		}

		if !perm.HasPermission(claims, ownedAppPermission) || !slices.Contains(claims.OwnedApps, appID) {
			errs.PermissionDeniedError().AppendDetails("权限不足", "鉴权失败").Abort(c)
			return
		}

		c.Set("app_access_scope", "owner")
		c.Set("app_access_app_id", appID)
	}
}
