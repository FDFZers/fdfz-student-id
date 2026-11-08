// Package middleware 提供通用 Gin 中间件：JWT 解析与鉴权、提权令牌校验、应用访问控制与请求体大小限制。
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

// ParseToken 解析请求中的访问令牌（优先 Authorization: Bearer，其次 access_token Cookie），
// 校验通过后把 claims 写入 token_claims 供后续处理器使用。
// 注意：未携带令牌时静默放行；令牌非法或过期时不中止请求（公开路由仍可访问），
// 而是把错误暂存到 token_error，由 RequireToken 在保护路由上返回精确的 401。
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
			// 解析失败不得写入 claims；保留错误信息供 RequireToken 区分过期与非法
			c.Set("token_error", err)
			return
		}
		c.Set("token_claims", claims)
	}
}

// RequireToken 要求请求已通过 ParseToken 解析出有效令牌，否则以 invalid_token 中止请求。
// 注意：本中间件依赖 ParseToken 先执行；存在 token_error 时按过期/非法返回精确 401。
func RequireToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.IsAborted() {
			return
		}
		if _, exists := c.Get("token_claims"); !exists {
			if value, ok := c.Get("token_error"); ok {
				if tokenErr, ok := value.(error); ok && tokenErr != nil {
					if errors.Is(tokenErr, jwt.ErrTokenExpired) {
						errs.TokenExpiredError().AppendDetails("令牌已过期").Abort(c)
						return
					}
					errs.InvalidTokenError().AppendDetails("令牌格式错误").Abort(c)
					return
				}
			}
			errs.InvalidTokenError().AppendDetails("未提供令牌").Abort(c)
			return
		}
	}
}

// RequirePermission 要求当前令牌同时具备全部指定权限，否则以 permission_denied 中止请求。
func RequirePermission(permissions ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		RequireToken()(c)
		if c.IsAborted() {
			return
		}
		for _, permission := range permissions {
			if !perm.HasPermission(handling.MustGetClaims(c), permission) {
				errs.PermissionDeniedError().AppendDetails("权限不足").Abort(c)
				return
			}
		}
	}
}

// ValidateStepupToken 校验 stepup_token Cookie：签名与有效期、令牌类型、关联会话是否仍有效，
// 以及用户级提权撤销标记；通过后把提权令牌的 claims 写入 token_claims 并返回 nil。
// 注意：本函数只返回错误，不写响应；调用方需自行 Abort 或交由处理链返回。
func ValidateStepupToken(c *gin.Context) *errs.Error {
	token, e := c.Cookie("stepup_token")
	if token == "" || errors.Is(e, http.ErrNoCookie) {
		return errs.TokenExpiredError().AppendDetails("未提供提权令牌")
	} else if e != nil {
		return errs.InvalidTokenError().AppendDetails("提权令牌格式错误")
	}

	claims, e := crypto.ParseJWT(token)
	if e != nil {
		if errors.Is(e, jwt.ErrTokenExpired) {
			return errs.TokenExpiredError().AppendDetails("提权令牌已过期")
		}
		return errs.InvalidTokenError().AppendDetails("提权令牌格式错误")
	}
	if claims.TokenType != model.TokenTypeStepup {
		return errs.InvalidTokenError().AppendDetails("令牌类型错误")
	}

	if !claims.SessionID.Valid {
		return errs.InvalidTokenError().AppendDetails("会话 ID 格式错误")
	}
	sessionID, e := uuid.Parse(claims.SessionID.String)
	if e != nil {
		return errs.InvalidTokenError().AppendDetails("会话 ID 格式错误")
	}
	session, err := auth.GetSessionByUUID(c.Request.Context(), sessionID)
	if err != nil {
		return err
	}
	if session == nil || session.UserID != claims.UserID ||
		session.RevokedAt != nil || !time.Now().Before(session.ExpiresAt) {
		return errs.InvalidTokenError().AppendDetails("会话已失效")
	}

	revokedAt, revokedErr := auth.GetStepupRevokedAt(c.Request.Context(), claims.UserID)
	if revokedErr != nil {
		return revokedErr
	} else if !revokedAt.IsZero() && claims.IssuedAt != nil && !claims.IssuedAt.Time.After(revokedAt) {
		return errs.InvalidTokenError().AppendDetails("提权令牌已失效")
	}

	c.Set("token_claims", claims)
	return nil
}

// RequireStepupToken 要求请求携带有效提权令牌（stepup_token Cookie），否则以 401 中止请求。
func RequireStepupToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := ValidateStepupToken(c); err != nil {
			err.Abort(c)
			return
		}
	}
}

// RequireAppAccess 校验当前用户对路由参数 appParam 指定应用的访问权限。
// 持有 globalPermission 时放行并写入 app_access_scope=global；否则要求持有 ownedAppPermission
// 且应用在令牌的 owned_apps 中，写入 app_access_scope=owner 与 app_access_app_id。
func RequireAppAccess(appParam string, globalPermission string, ownedAppPermission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		RequireToken()(c)
		if c.IsAborted() {
			return
		}

		claims := handling.GetClaimsOrNil(c)
		if claims.TokenType != model.TokenTypeUser {
			errs.InvalidTokenError().AppendDetails("令牌类型错误").Abort(c)
			return
		}

		if perm.HasPermission(claims, globalPermission) {
			c.Set("app_access_scope", "global")
			return
		}

		appID, err := strconv.ParseInt(c.Param(appParam), 10, 64)
		if err != nil || appID <= 0 {
			errs.BadRequestError().AppendDetails("应用 ID 格式错误").Abort(c)
			return
		}

		if !perm.HasPermission(claims, ownedAppPermission) || !slices.Contains(claims.OwnedApps, appID) {
			errs.PermissionDeniedError().AppendDetails("权限不足").Abort(c)
			return
		}

		c.Set("app_access_scope", "owner")
		c.Set("app_access_app_id", appID)
	}
}
