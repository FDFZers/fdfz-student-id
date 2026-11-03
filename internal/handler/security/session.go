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

type sessionInfo struct {
	UUID          string     `json:"uuid"`
	IsCurrent     bool       `json:"is_current"`
	IsTemporary   bool       `json:"is_temporary"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	ExpiresAt     time.Time  `json:"expires_at"`
	LastUsedAt    *time.Time `json:"last_used_at"`
	LastIP        *string    `json:"last_ip"`
	LastUserAgent string     `json:"last_user_agent"`
}

func currentSessionUUID(claims *model.RegisteredTokenClaims) *uuid.UUID {
	if claims.SessionID.Valid {
		if id, e := uuid.Parse(claims.SessionID.String); e == nil {
			return &id
		}
	}
	if id, e := uuid.Parse(claims.ID); e == nil {
		return &id
	}
	return nil
}

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

func listSessionsHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)

	selfID, err := handling.ParseUserID(c, claims.UserID, "userID")
	if err != nil {
		return err
	}

	var allowed bool
	if selfID == claims.UserID {
		allowed = perm.HasPermission(claims, perm.PermUserSessionRead)
	} else {
		allowed = perm.HasPermission(claims, perm.PermUsersSessionRead)
	}
	if !allowed {
		return errs.PermissionDeniedError().AppendDetails("权限不足", "鉴权失败").Seal()
	}

	if err := handling.EnsureUserExists(c, selfID); err != nil {
		return err
	}

	return serveUserSessionList(c, claims, selfID)
}

func revokeSessionsHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)

	selfID, err := handling.ParseUserID(c, claims.UserID, "userID")
	if err != nil {
		return err
	}

	var allowed bool
	if selfID == claims.UserID {
		allowed = perm.HasPermission(claims, perm.PermUserSessionWrite)
	} else {
		allowed = perm.HasPermission(claims, perm.PermUsersSessionWrite)
	}
	if !allowed {
		return errs.PermissionDeniedError().AppendDetails("权限不足", "鉴权失败").Seal()
	}

	if err := handling.EnsureUserExists(c, selfID); err != nil {
		return err
	}

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

func revokeSessionHandler(c *gin.Context) *errs.Error {
	claims := handling.MustGetClaims(c)

	selfID, err := handling.ParseUserID(c, claims.UserID, "userID")
	if err != nil {
		return err
	}

	var allowed bool
	if selfID == claims.UserID {
		allowed = perm.HasPermission(claims, perm.PermUserSessionWrite)
	} else {
		allowed = perm.HasPermission(claims, perm.PermUsersSessionWrite)
	}
	if !allowed {
		return errs.PermissionDeniedError().AppendDetails("权限不足", "鉴权失败").Seal()
	}

	if err := handling.EnsureUserExists(c, selfID); err != nil {
		return err
	}

	sessionID, e := uuid.Parse(c.Param("id"))
	if e != nil {
		return errs.BadRequestError().AppendDetails("无效的会话 ID")
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

	if currentID := currentSessionUUID(claims); currentID != nil && sessionID == *currentID {
		handling.ClearSessionCookies(c)
	}

	c.JSON(http.StatusOK, gin.H{})
	return nil
}
