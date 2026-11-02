package security

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/service/auth"
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

func listSessionsHandler(c *gin.Context) *errs.Error {
	claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)
	currentID := uuid.MustParse(claims.SessionID.String)

	sessions, err := auth.ListUserSessions(c.Request.Context(), claims.UserID)
	if err != nil {
		return err
	}

	results := make([]sessionInfo, 0, len(sessions))
	for _, session := range sessions {
		results = append(results, sessionInfo{
			UUID:          session.UUID.String(),
			IsCurrent:     session.UUID == currentID,
			IsTemporary:   session.IsTemporary,
			CreatedAt:     session.CreatedAt,
			UpdatedAt:     session.UpdatedAt,
			ExpiresAt:     session.ExpiresAt,
			LastUsedAt:    session.LastUsedAt,
			LastIP:        session.LastIP,
			LastUserAgent: session.LastUserAgent,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"sessions": results,
	})
	return nil
}

func revokeSessionHandler(c *gin.Context) *errs.Error {
	claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)

	targetID, e := uuid.Parse(c.Param("id"))
	if e != nil {
		return errs.BadRequestError().AppendDetails("无效的会话 ID")
	}

	currentID := uuid.MustParse(claims.SessionID.String)
	isCurrent := targetID == currentID

	session, err := auth.GetSessionByUUID(c.Request.Context(), targetID)
	if err != nil {
		if err.Info.Error == "not_found" {
			return errs.NotFoundError().AppendDetails("会话不存在")
		}
		return err
	}
	if session.UserID != claims.UserID {
		return errs.NotFoundError().AppendDetails("会话不存在")
	}
	if session.RevokedAt != nil || !time.Now().Before(session.ExpiresAt) {
		return errs.NotFoundError().AppendDetails("会话不存在或已失效")
	}

	if err := auth.RevokeSession(c.Request.Context(), targetID); err != nil {
		return err
	}

	if isCurrent {
		handling.ClearSessionCookies(c)
	}

	c.JSON(http.StatusOK, gin.H{})
	return nil
}

func revokeAllSessionsHandler(c *gin.Context) *errs.Error {
	claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)

	if err := auth.RevokeAllUserSessions(c.Request.Context(), claims.UserID); err != nil {
		return err
	}

	handling.ClearSessionCookies(c)

	c.JSON(http.StatusOK, gin.H{})
	return nil
}
