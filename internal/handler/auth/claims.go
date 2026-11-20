package auth

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	appsvc "fdfz-student-id/internal/service/app"
	permsvc "fdfz-student-id/internal/service/perm"
	usersvc "fdfz-student-id/internal/service/user"
	"fdfz-student-id/internal/util/handling"
	"net/http"

	"github.com/gin-gonic/gin"
)

// claimsResponse 是访问令牌的「可读声明」，用于前端做权限门控与展示。
type claimsResponse struct {
	UserID      int64           `json:"user_id"`
	TokenType   model.TokenType `json:"token_type"`
	Permissions []string        `json:"permissions"`
	OwnedApps   []int64         `json:"owned_apps"`
	AppID       *string         `json:"app_id,omitempty"`
	AuthID      *int64          `json:"auth_id,omitempty"`
	SessionID   *string         `json:"session_id,omitempty"`
	IsTemporary bool            `json:"is_temporary"`
	// PasswordResetRequired 表示管理员重置过密码，前端应提示用户尽快重设。
	PasswordResetRequired bool   `json:"password_reset_required"`
	Issuer                string `json:"iss"`
	ExpiresAt             int64  `json:"exp,omitempty"`
	IssuedAt              int64  `json:"iat,omitempty"`
	TokenID               string `json:"jti,omitempty"`
}

// claimsHandler 返回当前令牌的完整声明：权限 ID 已还原为具体权限串，
func claimsHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)

	resp := claimsResponse{
		UserID:      claims.UserID,
		TokenType:   claims.TokenType,
		Permissions: permsvc.Strings(claims.Permissions),
		OwnedApps:   []int64{},
		IsTemporary: claims.IsTemporary,
		Issuer:      claims.Issuer,
		TokenID:     claims.ID,
	}
	if claims.AppID.Valid {
		resp.AppID = &claims.AppID.String
	}
	if claims.AuthID.Valid {
		resp.AuthID = &claims.AuthID.Int64
	}
	if claims.SessionID.Valid {
		resp.SessionID = &claims.SessionID.String
	}
	if claims.ExpiresAt != nil {
		resp.ExpiresAt = claims.ExpiresAt.Unix()
	}
	if claims.IssuedAt != nil {
		resp.IssuedAt = claims.IssuedAt.Unix()
	}

	// 只有用户令牌用于应用所有者鉴权；OAuth 令牌本身受应用授权约束，不下发 owned_apps。
	if claims.TokenType == model.TokenTypeUser {
		ownedApps, err := appsvc.ListOwnedAppIDs(c.Request.Context(), claims.UserID)
		if err != nil {
			return err
		}
		resp.OwnedApps = ownedApps

		// 密码重设标记随时可能被管理员修改，需按用户当前状态返回。
		usr, err := usersvc.GetUserByID(c.Request.Context(), claims.UserID)
		if err != nil {
			return err
		}
		if usr != nil {
			resp.PasswordResetRequired = usr.PasswordResetRequired
		}
	}

	c.JSON(http.StatusOK, resp)
	return nil
}
