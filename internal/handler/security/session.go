package security

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/service/auth"
	"fdfz-student-id/internal/service/perm"
	"fdfz-student-id/internal/util/handling"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// sessionInfo 会话列表的响应项；不返回令牌哈希等敏感字段。
type sessionInfo struct {
	UUID          string     `json:"uuid"`
	IsCurrent     bool       `json:"is_current"`   // 是否为当前请求令牌所属的登录会话
	IsTemporary   bool       `json:"is_temporary"` // 临时会话刷新时不会延长有效期
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	ExpiresAt     time.Time  `json:"expires_at"`
	LastUsedAt    *time.Time `json:"last_used_at"`
	LastIP        *string    `json:"last_ip"`
	LastUserAgent string     `json:"last_user_agent"`
}

// currentSessionUUID 解析当前请求令牌所属的登录会话 UUID。
// 注意：提权令牌在 SessionID 中携带会话 UUID，访问令牌则只有 JWT ID，故需回退到 claims.ID。
func currentSessionUUID(claims *model.RegisteredTokenClaims) *uuid.UUID {
	if claims.SessionID.Valid {
		if id, err := uuid.Parse(claims.SessionID.String); err == nil {
			return &id
		}
	}
	if id, err := uuid.Parse(claims.ID); err == nil {
		return &id
	}
	return nil
}

// buildSessionInfos 把会话记录转换为响应项；currentID 为空时（查看他人会话）不标记当前会话。
func buildSessionInfos(sessions []*model.UserSession, currentID *uuid.UUID) []sessionInfo {
	results := make([]sessionInfo, 0, len(sessions))
	for _, session := range sessions {
		results = append(results, sessionInfo{
			UUID:          session.UUID.String(),
			IsCurrent:     currentID != nil && session.UUID == *currentID,
			IsTemporary:   session.IsTemporary,
			CreatedAt:     session.CreatedAt,
			UpdatedAt:     session.UpdatedAt,
			ExpiresAt:     session.ExpiresAt,
			LastUsedAt:    session.LastUsedAt,
			LastIP:        session.LastIP,
			LastUserAgent: session.LastUserAgent,
		})
	}
	return results
}

// serveUserSessionList 查询目标用户的有效会话并输出；仅当查看自己时标记当前会话。
func serveUserSessionList(
	c *gin.Context,
	claims *model.RegisteredTokenClaims,
	targetID int64,
) *errs.Error {
	sessions, err := auth.ListUserSessions(c.Request.Context(), targetID)
	if err != nil {
		return err
	}

	var currentID *uuid.UUID
	if targetID == claims.UserID {
		currentID = currentSessionUUID(claims)
	}

	c.JSON(http.StatusOK, gin.H{
		"sessions": buildSessionInfos(sessions, currentID),
	})
	return nil
}

// listSessionsHandler 列出用户的有效会话：查看自己需 user.session.read，查看他人需 users.session.read。
func listSessionsHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)

	selfID, err := handling.ParseUserID(c, claims.UserID, "userID")
	if err != nil {
		return err
	}

	// 自己与他人的会话读取使用不同权限
	var allowed bool
	if selfID == claims.UserID {
		allowed = perm.HasPermission(claims, perm.PermUserSessionRead)
	} else {
		allowed = perm.HasPermission(claims, perm.PermUsersSessionRead)
	}
	if !allowed {
		return errs.PermissionDeniedError().AppendDetails("权限不足").Seal()
	}

	if err := handling.EnsureUserExists(c, selfID); err != nil {
		return err
	}

	return serveUserSessionList(c, claims, selfID)
}

// revokeSessionsHandler 撤销目标用户的全部会话与提权令牌；撤销自己时同时清理 Cookie。
// 注意：撤销只影响后续刷新与提权校验，已签发的访问令牌在过期前仍然有效。
func revokeSessionsHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)

	selfID, err := handling.ParseUserID(c, claims.UserID, "userID")
	if err != nil {
		return err
	}

	// 自己与他人的会话撤销使用不同权限
	var allowed bool
	if selfID == claims.UserID {
		allowed = perm.HasPermission(claims, perm.PermUserSessionWrite)
	} else {
		allowed = perm.HasPermission(claims, perm.PermUsersSessionWrite)
	}
	if !allowed {
		return errs.PermissionDeniedError().AppendDetails("权限不足").Seal()
	}

	if err := handling.EnsureUserExists(c, selfID); err != nil {
		return err
	}

	// 撤销全部会话后提权令牌也无存在的意义，一并失效
	if err := auth.RevokeAllUserSessions(c.Request.Context(), selfID); err != nil {
		return err
	}
	if err := auth.RevokeUserStepups(c.Request.Context(), selfID); err != nil {
		return err
	}

	if selfID == claims.UserID {
		handling.ClearSessionCookies(c)
	}

	c.JSON(http.StatusOK, gin.H{})
	return nil
}

// revokeSessionHandler 撤销目标用户指定的单个会话；不允许撤销不属于目标用户的会话。
// 注意：撤销只影响后续刷新与提权校验，已签发的访问令牌在过期前仍然有效。
func revokeSessionHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)

	selfID, err := handling.ParseUserID(c, claims.UserID, "userID")
	if err != nil {
		return err
	}

	// 自己与他人的会话撤销使用不同权限
	var allowed bool
	if selfID == claims.UserID {
		allowed = perm.HasPermission(claims, perm.PermUserSessionWrite)
	} else {
		allowed = perm.HasPermission(claims, perm.PermUsersSessionWrite)
	}
	if !allowed {
		return errs.PermissionDeniedError().AppendDetails("权限不足").Seal()
	}

	if err := handling.EnsureUserExists(c, selfID); err != nil {
		return err
	}

	// 解析会话 ID 并校验归属与有效性
	sessionID, e := uuid.Parse(c.Param("id"))
	if e != nil {
		return errs.BadRequestError().AppendDetails("会话 ID 格式错误")
	}

	session, err := auth.GetSessionByUUID(c.Request.Context(), sessionID)
	if err != nil {
		if err.Info.Error == "not_found" {
			return errs.NotFoundError().AppendDetails("会话不存在")
		}
		return err
	}
	if session.UserID != selfID {
		return errs.NotFoundError().AppendDetails("会话不存在")
	}
	if session.RevokedAt != nil || !time.Now().Before(session.ExpiresAt) {
		return errs.NotFoundError().AppendDetails("会话不存在或已失效")
	}

	if err := auth.RevokeSession(c.Request.Context(), sessionID); err != nil {
		return err
	}

	// 撤销的是当前会话时清理 Cookie，避免客户端继续携带失效会话
	if currentID := currentSessionUUID(claims); currentID != nil && sessionID == *currentID {
		handling.ClearSessionCookies(c)
	}

	c.JSON(http.StatusOK, gin.H{})
	return nil
}
