package userperm

import (
	"context"
	"errors"
	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"

	"github.com/jackc/pgx/v5"
)

const (
	GrantListDefaultLimit int32 = 20
	GrantListMaxLimit     int32 = 100
)

// ---------------------------------------------------------------------------
// 用户直接权限授权 user_permission_grants
// ---------------------------------------------------------------------------

const grantUserPermissionSQL = `
INSERT INTO user_permission_grants
    (user_id, permission, granted_by_user_id, granted_by_app_id, valid_from, valid_until, note)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (user_id, permission) DO UPDATE
SET granted_by_user_id = EXCLUDED.granted_by_user_id,
    granted_by_app_id  = EXCLUDED.granted_by_app_id,
    valid_from         = EXCLUDED.valid_from,
    valid_until        = EXCLUDED.valid_until,
    note               = EXCLUDED.note
RETURNING id, user_id, permission, granted_by_user_id, granted_by_app_id,
          valid_from, valid_until, note, created_at, updated_at
`

func GrantUserPermission(ctx context.Context, g *model.UserPermissionGrant) *errs.Error {
	if g == nil {
		return errs.BadRequestError().AppendDetails("参数不能为空", "授权失败")
	}

	err := db.R.QueryRow(ctx, grantUserPermissionSQL,
		g.UserID, g.Permission, g.GrantedByUserID, g.GrantedByAppID,
		g.ValidFrom, g.ValidUntil, g.Note,
	).Scan(
		&g.ID, &g.UserID, &g.Permission, &g.GrantedByUserID, &g.GrantedByAppID,
		&g.ValidFrom, &g.ValidUntil, &g.Note, &g.CreatedAt, &g.UpdatedAt,
	)
	if err != nil {
		return errs.CreatePGError(err, "权限授权", "Failed to grant user permission").
			AppendDetails("授权失败")
	}
	return nil
}

const revokeUserPermissionSQL = `
DELETE FROM user_permission_grants WHERE user_id = $1 AND permission = $2
`

func RevokeUserPermission(ctx context.Context, userID int64, permission string) *errs.Error {
	if _, err := db.R.Exec(ctx, revokeUserPermissionSQL, userID, permission); err != nil {
		return errs.CreatePGError(err, "权限授权", "Failed to revoke user permission").
			AppendDetails("撤销权限失败")
	}
	return nil
}

const getUserPermissionGrantSQL = `
SELECT id, user_id, permission, granted_by_user_id, granted_by_app_id,
       valid_from, valid_until, note, created_at, updated_at
FROM user_permission_grants
WHERE user_id = $1 AND permission = $2
`

func GetUserPermissionGrant(ctx context.Context, userID int64, permission string) (*model.UserPermissionGrant, *errs.Error) {
	var g model.UserPermissionGrant
	err := db.R.QueryRow(ctx, getUserPermissionGrantSQL, userID, permission).Scan(
		&g.ID, &g.UserID, &g.Permission, &g.GrantedByUserID, &g.GrantedByAppID,
		&g.ValidFrom, &g.ValidUntil, &g.Note, &g.CreatedAt, &g.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, errs.CreatePGError(err, "权限授权", "Failed to get user permission grant").
			AppendDetails("获取权限授权失败")
	}
	return &g, nil
}

const countUserPermissionGrantsSQL = `
SELECT count(*) FROM user_permission_grants WHERE user_id = $1
`

const listUserPermissionGrantsSQL = `
SELECT id, user_id, permission, granted_by_user_id, granted_by_app_id,
       valid_from, valid_until, note, created_at, updated_at
FROM user_permission_grants
WHERE user_id = $1
ORDER BY id DESC
LIMIT $2 OFFSET $3
`

func ListUserPermissionGrants(ctx context.Context, userID int64, limit, offset int32) ([]*model.UserPermissionGrant, int32, *errs.Error) {
	if limit <= 0 {
		limit = GrantListDefaultLimit
	}
	if limit > GrantListMaxLimit {
		limit = GrantListMaxLimit
	}
	if offset < 0 {
		offset = 0
	}

	var count int32
	if err := db.R.QueryRow(ctx, countUserPermissionGrantsSQL, userID).Scan(&count); err != nil {
		return nil, 0, errs.CreatePGError(err, "权限授权", "Failed to count permission grants").
			AppendDetails("权限授权列表获取失败")
	}

	rows, err := db.R.Query(ctx, listUserPermissionGrantsSQL, userID, limit, offset)
	if err != nil {
		return nil, 0, errs.CreatePGError(err, "权限授权", "Failed to query permission grants").
			AppendDetails("权限授权列表获取失败")
	}

	grants, e := collectUserPermissionGrants(rows, "权限授权列表")
	if e != nil {
		return nil, 0, e
	}
	return grants, count, nil
}

func collectUserPermissionGrants(rows pgx.Rows, item string) ([]*model.UserPermissionGrant, *errs.Error) {
	defer rows.Close()

	grants := make([]*model.UserPermissionGrant, 0)
	for rows.Next() {
		var g model.UserPermissionGrant
		if err := rows.Scan(
			&g.ID, &g.UserID, &g.Permission, &g.GrantedByUserID, &g.GrantedByAppID,
			&g.ValidFrom, &g.ValidUntil, &g.Note, &g.CreatedAt, &g.UpdatedAt,
		); err != nil {
			return nil, errs.CreatePGError(err, item, "Failed to scan permission grant").
				AppendDetails(item + "获取失败")
		}
		grants = append(grants, &g)
	}
	if err := rows.Err(); err != nil {
		return nil, errs.CreatePGError(err, item, "Failed to iterate permission grants").
			AppendDetails(item + "获取失败")
	}
	return grants, nil
}

// ---------------------------------------------------------------------------
// 用户有效权限 = 有效用户组权限（含 permission_implies 递归）∪ 有效直接授权
// ---------------------------------------------------------------------------

const listUserEffectivePermissionsSQL = `
WITH RECURSIVE role_expanded AS (
    SELECT rp.permission_id AS id
    FROM user_roles ur
    JOIN role_permissions rp ON rp.role_id = ur.role_id
    WHERE ur.user_id = $1
      AND (ur.valid_from  IS NULL OR ur.valid_from  <= now())
      AND (ur.valid_until IS NULL OR ur.valid_until >  now())
    UNION
    SELECT pi.implied_permission_id
    FROM permission_implies pi
    JOIN role_expanded r ON pi.permission_id = r.id
)
SELECT DISTINCT a.namespace || ':' || pd.value AS permission
FROM permission_defs pd
JOIN oauth_apps a ON a.id = pd.app_id
JOIN role_expanded r ON r.id = pd.id
WHERE a.status = 'active' AND a.deleted_at IS NULL
UNION
SELECT g.permission
FROM user_permission_grants g
JOIN oauth_apps a ON a.id = g.granted_by_app_id
    AND a.status = 'active' AND a.deleted_at IS NULL
JOIN permission_defs pd ON pd.app_id = a.id
    AND g.permission = a.namespace || ':' || pd.value
WHERE g.user_id = $1
  AND (g.valid_from  IS NULL OR g.valid_from  <= now())
  AND (g.valid_until IS NULL OR g.valid_until >  now())
ORDER BY 1
`

func ListUserEffectivePermissions(ctx context.Context, userID int64) ([]string, *errs.Error) {
	rows, err := db.R.Query(ctx, listUserEffectivePermissionsSQL, userID)
	if err != nil {
		return nil, errs.CreatePGError(err, "用户权限", "Failed to query effective permissions").
			AppendDetails("用户权限获取失败")
	}
	defer rows.Close()

	perms := make([]string, 0)
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, errs.CreatePGError(err, "用户权限", "Failed to scan effective permission").
				AppendDetails("用户权限获取失败")
		}
		perms = append(perms, p)
	}
	if err := rows.Err(); err != nil {
		return nil, errs.CreatePGError(err, "用户权限", "Failed to iterate effective permissions").
			AppendDetails("用户权限获取失败")
	}
	return perms, nil
}
