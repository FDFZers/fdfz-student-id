package auth

import (
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/service/auth"
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

func currentSessionID(claims *model.RegisteredTokenClaims) (uuid.UUID, *errs.Error) {
	id, err := uuid.Parse(claims.ID)
	if err != nil {
		return uuid.Nil, errs.InvalidTokenError().AppendDetails("无效的会话", "鉴权失败")
	}
	return id, nil
}

func listSessionsHandler(c *gin.Context) {
	claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)

	currentID, err := currentSessionID(claims)
	if err != nil {
		err.AppendDetails("会话列表获取失败").Respond(c)
		return
	}

	sessions, err := auth.ListUserSessions(c.Request.Context(), claims.UserID)
	if err != nil {
		err.AppendDetails("会话列表获取失败").Respond(c)
		return
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
}

func revokeSessionHandler(c *gin.Context) {
	claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)

	targetID, e := uuid.Parse(c.Param("id"))
	if e != nil {
		errs.BadRequestError().AppendDetails("无效的会话 ID", "会话撤销失败").Respond(c)
		return
	}

	currentID, err := currentSessionID(claims)
	if err != nil {
		err.AppendDetails("会话撤销失败").Respond(c)
		return
	}
	isCurrent := targetID == currentID

	session, err := auth.GetSessionByUUID(c.Request.Context(), targetID)
	if err != nil {
		if err.Info.Error == "not_found" {
			errs.NotFoundError().AppendDetails("会话不存在", "会话撤销失败").Respond(c)
			return
		}
		err.AppendDetails("会话撤销失败").Respond(c)
		return
	}
	if session.UserID != claims.UserID {
		errs.NotFoundError().AppendDetails("会话不存在", "会话撤销失败").Respond(c)
		return
	}
	if session.RevokedAt != nil || !time.Now().Before(session.ExpiresAt) {
		errs.NotFoundError().AppendDetails("会话不存在或已失效", "会话撤销失败").Respond(c)
		return
	}

	if err := auth.RevokeSession(c.Request.Context(), targetID); err != nil {
		err.AppendDetails("会话撤销失败").Respond(c)
		return
	}

	if isCurrent {
		clearSessionCookies(c)
	}

	c.JSON(http.StatusOK, gin.H{})
}

func revokeAllSessionsHandler(c *gin.Context) {
	claims := c.MustGet("token_claims").(*model.RegisteredTokenClaims)

	if err := auth.RevokeAllUserSessions(c.Request.Context(), claims.UserID); err != nil {
		err.AppendDetails("会话撤销失败").Respond(c)
		return
	}

	clearSessionCookies(c)

	c.JSON(http.StatusOK, gin.H{})
}
