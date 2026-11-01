package auth

import (
	"context"
	"fdfz-student-id/internal/cfg"
	"time"

	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// 创建会话
// ---------------------------------------------------------------------------

const createSessionSQL = `
INSERT INTO user_sessions (
    user_id, session_token_hash, is_temporary, expires_at, last_ip, last_user_agent
) VALUES ($1, $2, $3, $4, $5, $6)
RETURNING uuid, created_at, updated_at
`

func CreateSession(ctx context.Context, s *model.UserSession) *errs.Error {
	err := db.R.QueryRow(ctx, createSessionSQL,
		s.UserID,
		s.SessionTokenHash,
		s.IsTemporary,
		s.ExpiresAt,
		s.LastIP,
		s.LastUserAgent,
	).Scan(
		&s.UUID,
		&s.CreatedAt,
		&s.UpdatedAt,
	)
	if err != nil {
		return errs.CreatePGError(err, "用户会话", "Failed to create session").AppendDetails("用户会话创建失败")
	}
	return nil
}

// ---------------------------------------------------------------------------
// 获取会话
// ---------------------------------------------------------------------------

const getSessionByUUIDSQL = `
SELECT uuid, user_id, session_token_hash, is_temporary,
    created_at, updated_at, expires_at, last_used_at, revoked_at,
    host(last_ip) AS last_ip, last_user_agent
FROM user_sessions
WHERE uuid = $1
`

const getSessionByTokenHashSQL = `
SELECT uuid, user_id, session_token_hash, is_temporary,
    created_at, updated_at, expires_at, last_used_at, revoked_at,
    host(last_ip) AS last_ip, last_user_agent
FROM user_sessions
WHERE session_token_hash = $1 AND revoked_at IS NULL AND expires_at > now()
`

func GetSessionByUUID(
	ctx context.Context,
	id uuid.UUID,
) (*model.UserSession, *errs.Error) {
	var s model.UserSession
	err := db.R.QueryRow(ctx, getSessionByUUIDSQL, id).Scan(
		&s.UUID,
		&s.UserID,
		&s.SessionTokenHash,
		&s.IsTemporary,
		&s.CreatedAt,
		&s.UpdatedAt,
		&s.ExpiresAt,
		&s.LastUsedAt,
		&s.RevokedAt,
		&s.LastIP,
		&s.LastUserAgent,
	)
	if err != nil {
		return nil, errs.CreatePGError(err, "用户会话", "Failed to get session by uuid").AppendDetails("用户会话获取失败")
	}
	return &s, nil
}

func GetSessionByTokenHash(
	ctx context.Context,
	tokenHash string,
) (*model.UserSession, *errs.Error) {
	var s model.UserSession
	err := db.R.QueryRow(ctx, getSessionByTokenHashSQL, tokenHash).Scan(
		&s.UUID,
		&s.UserID,
		&s.SessionTokenHash,
		&s.IsTemporary,
		&s.CreatedAt,
		&s.UpdatedAt,
		&s.ExpiresAt,
		&s.LastUsedAt,
		&s.RevokedAt,
		&s.LastIP,
		&s.LastUserAgent,
	)
	if err != nil {
		return nil, errs.CreatePGError(err, "用户会话", "Failed to get session by session token hash").AppendDetails("用户会话获取失败")
	}
	return &s, nil
}

// ---------------------------------------------------------------------------
// 列出用户的有效会话
// ---------------------------------------------------------------------------

const listUserSessionsSQL = `
SELECT uuid, user_id, session_token_hash, is_temporary,
    created_at, updated_at, expires_at, last_used_at, revoked_at,
    host(last_ip) AS last_ip, last_user_agent
FROM user_sessions
WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > now()
ORDER BY last_used_at DESC NULLS LAST, created_at DESC
`

func ListUserSessions(
	ctx context.Context,
	userID int64,
) ([]*model.UserSession, *errs.Error) {
	rows, err := db.R.Query(ctx, listUserSessionsSQL, userID)
	if err != nil {
		return nil, errs.CreatePGError(err, "用户会话", "Failed to list sessions").AppendDetails("用户会话列表获取失败")
	}
	defer rows.Close()

	var sessions []*model.UserSession
	for rows.Next() {
		var s model.UserSession
		if err := rows.Scan(
			&s.UUID,
			&s.UserID,
			&s.SessionTokenHash,
			&s.IsTemporary,
			&s.CreatedAt,
			&s.UpdatedAt,
			&s.ExpiresAt,
			&s.LastUsedAt,
			&s.RevokedAt,
			&s.LastIP,
			&s.LastUserAgent,
		); err != nil {
			return nil, errs.CreatePGError(err, "用户会话", "Failed to scan session").AppendDetails("用户会话列表获取失败")
		}
		sessions = append(sessions, &s)
	}
	if err := rows.Err(); err != nil {
		return nil, errs.CreatePGError(err, "用户会话", "Failed to list sessions").AppendDetails("用户会话列表获取失败")
	}
	return sessions, nil
}

// ---------------------------------------------------------------------------
// 更新会话
// ---------------------------------------------------------------------------

const updateSessionClientSQL = `
UPDATE user_sessions
SET last_used_at = now(),
    session_token_hash = $2,
    last_ip = $3,
    last_user_agent = $4,
    expires_at = CASE
        WHEN is_temporary = false THEN $5
        ELSE expires_at
    END
WHERE uuid = $1 AND revoked_at IS NULL
RETURNING expires_at
`

func UpdateSessionClient(
	c *gin.Context,
	id uuid.UUID,
	sessionTokenHash string,
) (time.Time, *errs.Error) {
	var expiresAt time.Time
	err := db.R.QueryRow(c.Request.Context(), updateSessionClientSQL, id, sessionTokenHash, c.ClientIP(), c.Request.UserAgent(), time.Now().Add(cfg.C.PermSessionTokenTTL)).Scan(&expiresAt)
	if err != nil {
		return expiresAt, errs.CreatePGError(err, "用户会话", "Failed to update session").AppendDetails("用户会话更新失败")
	}
	return expiresAt, nil
}

// ---------------------------------------------------------------------------
// 撤销会话
// ---------------------------------------------------------------------------

const revokeSessionSQL = `
UPDATE user_sessions
SET revoked_at = now()
WHERE uuid = $1 AND revoked_at IS NULL
RETURNING session_token_hash
`

func RevokeSession(ctx context.Context, id uuid.UUID) *errs.Error {
	var tokenHash string
	err := db.R.QueryRow(ctx, revokeSessionSQL, id).Scan(&tokenHash)
	if err != nil {
		return errs.CreatePGError(err, "用户会话", "Failed to revoke session").AppendDetails("用户会话撤销失败")
	}
	return nil
}

const revokeAllUserSessionsSQL = `
UPDATE user_sessions
SET revoked_at = now()
WHERE user_id = $1 AND revoked_at IS NULL
RETURNING uuid, session_token_hash
`

func RevokeAllUserSessions(ctx context.Context, userID int64) *errs.Error {
	rows, err := db.R.Query(ctx, revokeAllUserSessionsSQL, userID)
	if err != nil {
		return errs.CreatePGError(err, "用户会话", "Failed to revoke sessions").AppendDetails("用户会话撤销失败")
	}
	defer rows.Close()

	for rows.Next() {
		var id uuid.UUID
		var tokenHash string
		if err := rows.Scan(&id, &tokenHash); err != nil {
			return errs.CreatePGError(err, "用户会话", "Failed to scan revoked session").AppendDetails("用户会话撤销失败")
		}
	}
	if err := rows.Err(); err != nil {
		return errs.CreatePGError(err, "用户会话", "Failed to revoke sessions").AppendDetails("用户会话撤销失败")
	}
	return nil
}

// ---------------------------------------------------------------------------
// 删除会话
// ---------------------------------------------------------------------------
const deleteSessionSQL = `
DELETE FROM user_sessions
WHERE uuid = $1
`

func DeleteSession(ctx context.Context, id uuid.UUID) *errs.Error {
	if _, err := db.R.Exec(ctx, deleteSessionSQL, id); err != nil {
		return errs.CreatePGError(err, "用户会话", "Failed to delete session").AppendDetails("用户会话删除失败")
	}
	return nil
}

// ---------------------------------------------------------------------------
// 清理过期 / 已撤销的会话
// ---------------------------------------------------------------------------

const deleteStaleSessionsSQL = `
DELETE FROM user_sessions
WHERE (expires_at < now() - interval '30 days')
   OR (revoked_at IS NOT NULL AND revoked_at < now() - interval '30 days')
`

func DeleteStaleSessions(ctx context.Context) (int64, *errs.Error) {
	tag, err := db.R.Exec(ctx, deleteStaleSessionsSQL)
	if err != nil {
		return 0, errs.CreatePGError(err, "用户会话", "Failed to delete stale sessions").AppendDetails("过期会话清理失败")
	}
	return tag.RowsAffected(), nil
}
