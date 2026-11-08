// Package auth 实现鉴权会话、用户会话、提权撤销与认证频率限制等认证服务。
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

// createSessionSQL 写入用户会话，并由数据库回填 uuid、创建/更新时间。
const createSessionSQL = `
INSERT INTO user_sessions (
    user_id, session_token_hash, is_temporary, expires_at, last_ip, last_user_agent
) VALUES ($1, $2, $3, $4, $5, $6)
RETURNING uuid, created_at, updated_at
`

// CreateSession 在 user_sessions 表创建用户会话，并把数据库生成的时间戳回写到 s。
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
		return errs.CreatePGError(err, "用户会话", "Failed to create session")
	}
	return nil
}

// ---------------------------------------------------------------------------
// 获取会话
// ---------------------------------------------------------------------------

// getSessionByUUIDSQL 按 uuid 查询会话，包含已过期与已撤销的记录。
const getSessionByUUIDSQL = `
SELECT uuid, user_id, session_token_hash, is_temporary,
    created_at, updated_at, expires_at, last_used_at, revoked_at,
    host(last_ip) AS last_ip, last_user_agent
FROM user_sessions
WHERE uuid = $1
`

// getSessionByTokenHashSQL 按会话令牌哈希查询仍有效（未撤销且未过期）的会话。
const getSessionByTokenHashSQL = `
SELECT uuid, user_id, session_token_hash, is_temporary,
    created_at, updated_at, expires_at, last_used_at, revoked_at,
    host(last_ip) AS last_ip, last_user_agent
FROM user_sessions
WHERE session_token_hash = $1 AND revoked_at IS NULL AND expires_at > now()
`

// GetSessionByUUID 按会话 uuid 查询用户会话。
// 注意：记录不存在时返回 not_found 错误而不是 (nil, nil)，调用方应据此区分「不存在」。
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
		return nil, errs.CreatePGError(err, "用户会话", "Failed to get session by uuid")
	}
	return &s, nil
}

// GetSessionByTokenHash 按会话令牌哈希查询仍有效的用户会话，用于刷新访问令牌。
// 注意：默认只返回未撤销且未过期的会话；记录不存在时返回 not_found 错误。
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
		return nil, errs.CreatePGError(err, "用户会话", "Failed to get session by session token hash")
	}
	return &s, nil
}

// ---------------------------------------------------------------------------
// 列出用户的有效会话
// ---------------------------------------------------------------------------

// listUserSessionsSQL 列出用户当前有效的会话，最近使用的排在前面。
const listUserSessionsSQL = `
SELECT uuid, user_id, session_token_hash, is_temporary,
    created_at, updated_at, expires_at, last_used_at, revoked_at,
    host(last_ip) AS last_ip, last_user_agent
FROM user_sessions
WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > now()
ORDER BY last_used_at DESC NULLS LAST, created_at DESC
`

// ListUserSessions 列出指定用户所有未撤销且未过期的会话。
func ListUserSessions(
	ctx context.Context,
	userID int64,
) ([]*model.UserSession, *errs.Error) {
	rows, err := db.R.Query(ctx, listUserSessionsSQL, userID)
	if err != nil {
		return nil, errs.CreatePGError(err, "用户会话", "Failed to list sessions")
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
			return nil, errs.CreatePGError(err, "用户会话", "Failed to scan session")
		}
		sessions = append(sessions, &s)
	}
	if err := rows.Err(); err != nil {
		return nil, errs.CreatePGError(err, "用户会话", "Failed to list sessions")
	}
	return sessions, nil
}

// ---------------------------------------------------------------------------
// 更新会话
// ---------------------------------------------------------------------------

// updateSessionClientSQL 轮换会话令牌哈希并刷新最近使用时间与客户端信息。
// 注意：只有非临时会话会把 expires_at 续期到新的过期时间，临时会话保持原过期时间。
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

// UpdateSessionClient 刷新会话的令牌哈希、最近使用时间、IP 与 UA，并返回会话新的过期时间。
// 注意：会轮换 session_token_hash，旧的会话令牌随即失效。
func UpdateSessionClient(
	c *gin.Context,
	id uuid.UUID,
	sessionTokenHash string,
) (time.Time, *errs.Error) {
	var expiresAt time.Time
	err := db.R.QueryRow(c.Request.Context(), updateSessionClientSQL, id, sessionTokenHash, c.ClientIP(), c.Request.UserAgent(), time.Now().Add(cfg.C.PermSessionTokenTTL)).Scan(&expiresAt)
	if err != nil {
		return expiresAt, errs.CreatePGError(err, "用户会话", "Failed to update session")
	}
	return expiresAt, nil
}

// ---------------------------------------------------------------------------
// 撤销会话
// ---------------------------------------------------------------------------

// revokeSessionSQL 把单个会话标记为已撤销，返回其令牌哈希。
const revokeSessionSQL = `
UPDATE user_sessions
SET revoked_at = now()
WHERE uuid = $1 AND revoked_at IS NULL
RETURNING session_token_hash
`

// RevokeSession 撤销指定会话（登出）。
// 注意：已撤销的会话不会重复更新，此时再撤销会返回 not_found 错误。
func RevokeSession(ctx context.Context, id uuid.UUID) *errs.Error {
	var tokenHash string
	err := db.R.QueryRow(ctx, revokeSessionSQL, id).Scan(&tokenHash)
	if err != nil {
		return errs.CreatePGError(err, "用户会话", "Failed to revoke session")
	}
	return nil
}

// revokeAllUserSessionsSQL 撤销用户全部未撤销会话，返回被撤销会话的 uuid 与令牌哈希。
const revokeAllUserSessionsSQL = `
UPDATE user_sessions
SET revoked_at = now()
WHERE user_id = $1 AND revoked_at IS NULL
RETURNING uuid, session_token_hash
`

// RevokeAllUserSessions 撤销指定用户的全部有效会话（改密、注销等场景）。
func RevokeAllUserSessions(ctx context.Context, userID int64) *errs.Error {
	rows, err := db.R.Query(ctx, revokeAllUserSessionsSQL, userID)
	if err != nil {
		return errs.CreatePGError(err, "用户会话", "Failed to revoke sessions")
	}
	defer rows.Close()

	for rows.Next() {
		var id uuid.UUID
		var tokenHash string
		if err := rows.Scan(&id, &tokenHash); err != nil {
			return errs.CreatePGError(err, "用户会话", "Failed to scan revoked session")
		}
	}
	if err := rows.Err(); err != nil {
		return errs.CreatePGError(err, "用户会话", "Failed to revoke sessions")
	}
	return nil
}

// revokeOtherUserSessionsSQL 撤销用户除指定会话外的其他未撤销会话。
const revokeOtherUserSessionsSQL = `
UPDATE user_sessions
SET revoked_at = now()
WHERE user_id = $1 AND uuid <> $2 AND revoked_at IS NULL
`

// RevokeOtherUserSessions 撤销用户除 keepSessionID 外的其他会话（修改密码后保留当前会话）。
func RevokeOtherUserSessions(ctx context.Context, userID int64, keepSessionID uuid.UUID) *errs.Error {
	if _, err := db.R.Exec(ctx, revokeOtherUserSessionsSQL, userID, keepSessionID); err != nil {
		return errs.CreatePGError(err, "用户会话", "Failed to revoke other sessions")
	}
	return nil
}

// ---------------------------------------------------------------------------
// 删除会话
// ---------------------------------------------------------------------------

// deleteSessionSQL 物理删除指定会话。
const deleteSessionSQL = `
DELETE FROM user_sessions
WHERE uuid = $1
`

// DeleteSession 物理删除会话，仅用于登录流程失败时回滚刚创建的会话。
func DeleteSession(ctx context.Context, id uuid.UUID) *errs.Error {
	if _, err := db.R.Exec(ctx, deleteSessionSQL, id); err != nil {
		return errs.CreatePGError(err, "用户会话", "Failed to delete session")
	}
	return nil
}

// ---------------------------------------------------------------------------
// 清理过期 / 已撤销的会话
// ---------------------------------------------------------------------------

// deleteStaleSessionsSQL 删除过期或撤销超过 30 天的会话记录。
const deleteStaleSessionsSQL = `
DELETE FROM user_sessions
WHERE (expires_at < now() - interval '30 days')
   OR (revoked_at IS NOT NULL AND revoked_at < now() - interval '30 days')
`

// DeleteStaleSessions 清理过期或撤销超过 30 天的会话记录，返回删除行数；由每日定时任务调用。
func DeleteStaleSessions(ctx context.Context) (int64, *errs.Error) {
	tag, err := db.R.Exec(ctx, deleteStaleSessionsSQL)
	if err != nil {
		return 0, errs.CreatePGError(err, "用户会话", "Failed to delete stale sessions")
	}
	return tag.RowsAffected(), nil
}
