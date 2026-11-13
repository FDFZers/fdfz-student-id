package middleware

import (
	"errors"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	authsvc "fdfz-student-id/internal/service/auth"
	permsvc "fdfz-student-id/internal/service/perm"
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
// 支持用户访问令牌、提权令牌与 OAuth 应用令牌；OAuth 令牌只做 JWT 签名与声明校验，
// 其权限完全来自签发时写入的 permissions，撤销授权不会追溯已签发的访问令牌。
// 令牌非法或过期时不中止请求，以便公开路由仍可访问。
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
			c.Set("token_error", err)
			return
		}
		if claims.UserID <= 0 {
			c.Set("token_error", errs.InvalidTokenError().AppendDetails("令牌缺少用户信息"))
			return
		}

		// 校验令牌类型与必填声明：OAuth 令牌必须携带 app_id，否则无法归属到应用。
		switch claims.TokenType {
		case model.TokenTypeUser, model.TokenTypeStepup:
		case model.TokenTypeOAuth:
			if !claims.AppID.Valid || claims.AppID.String == "" {
				c.Set("token_error", errs.InvalidTokenError().AppendDetails("令牌缺少应用信息"))
				return
			}
		default:
			c.Set("token_error", errs.InvalidTokenError().AppendDetails("令牌类型错误"))
			return
		}

		c.Set("token_claims", claims)
	}
}

// RequireToken 要求请求已通过 ParseToken 解析出有效令牌，否则以 invalid_token 中止请求。
// ParseToken 写入的 *errs.Error 会被原样返回，其余解析错误按过期/格式错误归类。
func RequireToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.IsAborted() {
			return
		}
		if _, exists := c.Get("token_claims"); !exists {
			if value, ok := c.Get("token_error"); ok {
				// ParseToken 抛出的业务错误（令牌类型错误等）直接原样返回。
				if err, ok := value.(*errs.Error); ok && err != nil {
					err.Abort(c)
					return
				}
				if e, ok := value.(error); ok && e != nil {
					if errors.Is(e, jwt.ErrTokenExpired) {
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

// RequireUserToken 要求令牌是用户访问令牌：提权令牌与 OAuth 应用令牌都不能访问这些接口。
// 用于 OAuth 授权确认、设备码确认与授权管理等必须由用户本人操作的端点。
func RequireUserToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		RequireToken()(c)
		if c.IsAborted() {
			return
		}
		claims := handling.GetClaimsOrNil(c)
		if claims == nil || claims.TokenType != model.TokenTypeUser {
			errs.InvalidTokenError().AppendDetails("令牌类型错误").Abort(c)
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
			if !permsvc.HasPermission(handling.MustGetClaims(c), permission) {
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
	session, err := authsvc.GetSessionByUUID(c.Request.Context(), sessionID)
	if err != nil {
		return err
	}
	if session == nil || session.UserID != claims.UserID ||
		session.RevokedAt != nil || !time.Now().Before(session.ExpiresAt) {
		return errs.InvalidTokenError().AppendDetails("会话已失效")
	}

	revokedAt, err := authsvc.GetStepupRevokedAt(c.Request.Context(), claims.UserID)
	if err != nil {
		return err
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

		if permsvc.HasPermission(claims, globalPermission) {
			c.Set("app_access_scope", "global")
			return
		}

		appID, err := strconv.ParseInt(c.Param(appParam), 10, 64)
		if err != nil || appID <= 0 {
			errs.BadRequestError().AppendDetails("应用 ID 格式错误").Abort(c)
			return
		}

		if !permsvc.HasPermission(claims, ownedAppPermission) || !slices.Contains(claims.OwnedApps, appID) {
			errs.PermissionDeniedError().AppendDetails("权限不足").Abort(c)
			return
		}

		c.Set("app_access_scope", "owner")
		c.Set("app_access_app_id", appID)
	}
}
