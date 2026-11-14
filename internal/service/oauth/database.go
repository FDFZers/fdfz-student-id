package oauth

import (
	"context"
	"errors"
	"time"

	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/util/handling"

	"github.com/guregu/null/v6"
	"github.com/jackc/pgx/v5"
)

// tokenAuthorization 是令牌签发时需要的授权、应用与用户状态。
type tokenAuthorization struct {
	Permissions   []string
	AuthStatus    model.AppAuthStatus
	AppStatus     model.AppStatus
	UserDeletedAt null.Time
}

// refreshTokenRecord 是刷新令牌轮换时需要的令牌、授权与用户状态。
type refreshTokenRecord struct {
	ID            int64
	ExpiresAt     time.Time
	AuthID        int64
	UserID        int64
	AppID         int64
	Permissions   []string
	AuthStatus    model.AppAuthStatus
	AppStatus     model.AppStatus
	UserDeletedAt null.Time
}

// UserAuthorization 是用户在账户设置中看到的授权记录。
type UserAuthorization struct {
	ID          int64               `json:"id"`
	App         *handling.AppInfo   `json:"app"`
	Permissions []string            `json:"permissions"`
	Status      model.AppAuthStatus `json:"status"`
	CreatedAt   time.Time           `json:"created_at"`
	UpdatedAt   time.Time           `json:"updated_at"`
	LastUsedAt  null.Time           `json:"last_used_at"`
}

// ---------------------------------------------------------------------------
// 授权
// ---------------------------------------------------------------------------

const getAuthorizationByUserAppSQL = `
SELECT id, user_id, app_id, permissions, status, created_at, updated_at, last_used_at
FROM oauth_authorizations
WHERE user_id = $1 AND app_id = $2
`

func getAuthorizationByUserApp(ctx context.Context, userID, appID int64) (*model.OAuthAuthorization, *errs.Error) {
	var a model.OAuthAuthorization
	err := db.R.QueryRow(ctx, getAuthorizationByUserAppSQL, userID, appID).Scan(
		&a.ID, &a.UserID, &a.AppID, &a.Permissions, &a.Status,
		&a.CreatedAt, &a.UpdatedAt, &a.LastUsedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, errs.CreatePGError(err, "OAuth 授权", "Failed to get oauth authorization")
	}
	return &a, nil
}

const upsertAuthorizationSQL = `
INSERT INTO oauth_authorizations (user_id, app_id, permissions, status)
VALUES ($1, $2, $3, 'active')
ON CONFLICT (user_id, app_id) DO UPDATE
SET permissions = EXCLUDED.permissions,
    status      = 'active'
RETURNING id
`

func upsertAuthorization(
	ctx context.Context,
	userID, appID int64,
	permissions []string,
) (int64, *errs.Error) {
	var authID int64
	if err := db.R.QueryRow(ctx, upsertAuthorizationSQL, userID, appID, permissions).Scan(&authID); err != nil {
		return 0, errs.CreatePGError(err, "OAuth 授权", "Failed to upsert oauth authorization")
	}
	return authID, nil
}

const loadAuthorizationForTokenSQL = `
SELECT a.permissions, a.status, app.status, u.deleted_at
FROM oauth_authorizations a
JOIN apps app ON app.id = a.app_id
JOIN users u ON u.id = a.user_id
WHERE a.id = $1 AND app.id = $2 AND u.id = $3
`

func loadAuthorizationForToken(
	ctx context.Context,
	dh db.Handle,
	authID, appID, userID int64,
) (*tokenAuthorization, *errs.Error) {
	var state tokenAuthorization
	err := dh.QueryRow(ctx, loadAuthorizationForTokenSQL, authID, appID, userID).Scan(
		&state.Permissions, &state.AuthStatus, &state.AppStatus, &state.UserDeletedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, errs.CreatePGError(err, "OAuth 授权", "Failed to load oauth authorization")
	}
	return &state, nil
}

const touchAuthorizationSQL = `UPDATE oauth_authorizations SET last_used_at = now() WHERE id = $1`

func touchAuthorization(ctx context.Context, dh db.Handle, authID int64) *errs.Error {
	if _, err := dh.Exec(ctx, touchAuthorizationSQL, authID); err != nil {
		return errs.CreatePGError(err, "OAuth 授权", "Failed to touch oauth authorization")
	}
	return nil
}

const getAuthorizationByIDSQL = `
SELECT id, user_id, app_id, permissions, status, created_at, updated_at, last_used_at
FROM oauth_authorizations
WHERE id = $1
`

// GetAuthorizationByID 供撤销前判断授权归属，决定需要 oauth.revoke 还是 oauths.revoke。
func GetAuthorizationByID(ctx context.Context, id int64) (*model.OAuthAuthorization, *errs.Error) {
	var a model.OAuthAuthorization
	err := db.R.QueryRow(ctx, getAuthorizationByIDSQL, id).Scan(
		&a.ID, &a.UserID, &a.AppID, &a.Permissions, &a.Status,
		&a.CreatedAt, &a.UpdatedAt, &a.LastUsedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, errs.CreatePGError(err, "OAuth 授权", "Failed to get oauth authorization")
	}
	return &a, nil
}

const deleteAuthorizationSQL = `DELETE FROM oauth_authorizations WHERE id = $1`

// DeleteAuthorization 撤销授权；刷新令牌由外键级联删除，已签发的 JWT 访问令牌仍可用至过期。
func DeleteAuthorization(ctx context.Context, id int64) *errs.Error {
	tag, err := db.R.Exec(ctx, deleteAuthorizationSQL, id)
	if err != nil {
		return errs.CreatePGError(err, "OAuth 授权", "Failed to revoke oauth authorization")
	}
	if tag.RowsAffected() == 0 {
		return errs.NotFoundError().AppendDetails("授权记录不存在")
	}
	return nil
}

const listUserAuthorizationsSQL = `
SELECT a.id, a.permissions, a.status, a.created_at, a.updated_at, a.last_used_at,
       app.id, app.namespace, app.owner_user_id, app.secret_hash, app.name, app.description,
       app.homepage_url, app.client_type, app.redirect_uris, app.requested_perms, app.status,
       app.created_at, app.updated_at, app.deleted_at
FROM oauth_authorizations a
JOIN apps app ON app.id = a.app_id AND app.deleted_at IS NULL
WHERE a.user_id = $1 AND a.status IN ('active', 'update_suspended')
ORDER BY (a.status <> 'active'), a.updated_at DESC, a.id DESC
`

func ListUserAuthorizations(
	ctx context.Context,
	userID int64,
) ([]*UserAuthorization, *errs.Error) {
	rows, err := db.R.Query(ctx, listUserAuthorizationsSQL, userID)
	if err != nil {
		return nil, errs.CreatePGError(err, "OAuth 授权", "Failed to list user oauth authorizations")
	}
	defer rows.Close()

	result := make([]*UserAuthorization, 0)
	for rows.Next() {
		var (
			item UserAuthorization
			app  model.OAuthApp
		)
		if err := rows.Scan(
			&item.ID, &item.Permissions, &item.Status, &item.CreatedAt, &item.UpdatedAt, &item.LastUsedAt,
			&app.ID, &app.Namespace, &app.OwnerUserID, &app.SecretHash, &app.Name, &app.Description,
			&app.HomepageURL, &app.ClientType, &app.RedirectURIs, &app.RequestedPerms, &app.Status,
			&app.CreatedAt, &app.UpdatedAt, &app.DeletedAt,
		); err != nil {
			return nil, errs.CreatePGError(err, "OAuth 授权", "Failed to scan user oauth authorization")
		}
		item.App = handling.AppJSON(&app)
		result = append(result, &item)
	}
	if err := rows.Err(); err != nil {
		return nil, errs.CreatePGError(err, "OAuth 授权", "Failed to iterate user oauth authorizations")
	}
	return result, nil
}

// ---------------------------------------------------------------------------
// 刷新令牌
// ---------------------------------------------------------------------------

const insertRefreshTokenSQL = `
INSERT INTO oauth_refresh_tokens (auth_id, token_hash, expires_at)
VALUES ($1, $2, $3)
`

func insertRefreshToken(
	ctx context.Context,
	dh db.Handle,
	authID int64,
	tokenHash string,
	expiresAt time.Time,
) *errs.Error {
	if _, err := dh.Exec(ctx, insertRefreshTokenSQL, authID, tokenHash, expiresAt); err != nil {
		return errs.CreatePGError(err, "OAuth 刷新令牌", "Failed to store oauth refresh token")
	}
	return nil
}

const deleteRefreshTokenByIDSQL = `DELETE FROM oauth_refresh_tokens WHERE id = $1`

// deleteRefreshTokenByID 删除单条刷新令牌；轮换时必须检查返回值，命中 0 行后继续签发会让同一令牌被重复使用。
func deleteRefreshTokenByID(ctx context.Context, dh db.Handle, refreshTokenID int64) (bool, *errs.Error) {
	tag, err := dh.Exec(ctx, deleteRefreshTokenByIDSQL, refreshTokenID)
	if err != nil {
		return false, errs.CreatePGError(err, "OAuth 刷新令牌", "Failed to delete oauth refresh token")
	}
	return tag.RowsAffected() == 1, nil
}

const loadRefreshTokenForUpdateSQL = `
SELECT rt.id, rt.expires_at,
       a.id, a.user_id, a.app_id, a.permissions, a.status,
       app.status, u.deleted_at
FROM oauth_refresh_tokens rt
JOIN oauth_authorizations a ON a.id = rt.auth_id
JOIN apps app ON app.id = a.app_id
JOIN users u ON u.id = a.user_id
WHERE rt.token_hash = $1
FOR UPDATE OF rt
`

// loadRefreshTokenForUpdate 必须用调用方的事务句柄 dh 执行，FOR UPDATE 行锁才会持有到事务提交。
func loadRefreshTokenForUpdate(
	ctx context.Context,
	dh db.Handle,
	tokenHash string,
) (*refreshTokenRecord, *errs.Error) {
	var record refreshTokenRecord
	err := dh.QueryRow(ctx, loadRefreshTokenForUpdateSQL, tokenHash).Scan(
		&record.ID, &record.ExpiresAt,
		&record.AuthID, &record.UserID, &record.AppID, &record.Permissions, &record.AuthStatus,
		&record.AppStatus, &record.UserDeletedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, errs.CreatePGError(err, "OAuth 刷新令牌", "Failed to load oauth refresh token")
	}
	return &record, nil
}

const findRefreshTokenOwnerSQL = `
SELECT rt.id, a.app_id
FROM oauth_refresh_tokens rt
JOIN oauth_authorizations a ON a.id = rt.auth_id
WHERE rt.token_hash = $1
`

func findRefreshTokenOwner(
	ctx context.Context,
	dh db.Handle,
	tokenHash string,
) (int64, int64, *errs.Error) {
	var refreshTokenID, appID int64
	err := dh.QueryRow(ctx, findRefreshTokenOwnerSQL, tokenHash).Scan(&refreshTokenID, &appID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, 0, nil
		}
		return 0, 0, errs.CreatePGError(err, "OAuth 刷新令牌", "Failed to look up oauth refresh token")
	}
	return refreshTokenID, appID, nil
}

const deleteStaleRefreshTokensSQL = `
DELETE FROM oauth_refresh_tokens
WHERE expires_at < now() - interval '30 days'
`

func DeleteStaleRefreshTokens(ctx context.Context) (int64, *errs.Error) {
	tag, err := db.R.Exec(ctx, deleteStaleRefreshTokensSQL)
	if err != nil {
		return 0, errs.CreatePGError(err, "OAuth 刷新令牌", "Failed to delete stale oauth refresh tokens")
	}
	return tag.RowsAffected(), nil
}
