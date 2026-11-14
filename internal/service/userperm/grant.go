package userperm

import (
	"context"
	"errors"
	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"

	"github.com/jackc/pgx/v5"
)

// 用户直接授权列表的分页限制。
const (
	GrantListDefaultLimit int32 = 20
	GrantListMaxLimit     int32 = 100
)

// ---------------------------------------------------------------------------
// 用户直接权限授权 user_permission_grants
// ---------------------------------------------------------------------------

// grantUserPermissionSQL 写入用户直接授权；同一用户与权限重复授权时覆盖授权人、有效期与备注。
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

// GrantUserPermission 授予或更新一条用户直接权限（按 user_id + permission upsert）。
// 注意：直接授权不进权限目录，因此不需要触发权限目录重载；生效范围由有效期字段决定。
func GrantUserPermission(ctx context.Context, g *model.UserPermissionGrant) *errs.Error {
	if g == nil {
		return errs.BadRequestError().AppendDetails("未提供参数")
	}

	err := db.R.QueryRow(ctx, grantUserPermissionSQL,
		g.UserID, g.Permission, g.GrantedByUserID, g.GrantedByAppID,
		g.ValidFrom, g.ValidUntil, g.Note,
	).Scan(
		&g.ID, &g.UserID, &g.Permission, &g.GrantedByUserID, &g.GrantedByAppID,
		&g.ValidFrom, &g.ValidUntil, &g.Note, &g.CreatedAt, &g.UpdatedAt,
	)
	if err != nil {
		return errs.CreatePGError(err, "权限授权", "Failed to grant user permission")
	}
	return nil
}

// revokeUserPermissionSQL 删除指定用户与权限的直接授权。
const revokeUserPermissionSQL = `
DELETE FROM user_permission_grants WHERE user_id = $1 AND permission = $2
`

// RevokeUserPermission 撤销一条用户直接授权；不存在时幂等成功。
func RevokeUserPermission(ctx context.Context, userID int64, permission string) *errs.Error {
	if _, err := db.R.Exec(ctx, revokeUserPermissionSQL, userID, permission); err != nil {
		return errs.CreatePGError(err, "权限授权", "Failed to revoke user permission")
	}
	return nil
}

// getUserPermissionGrantSQL 按用户与完整权限值查询一条直接授权。
const getUserPermissionGrantSQL = `
SELECT id, user_id, permission, granted_by_user_id, granted_by_app_id,
       valid_from, valid_until, note, created_at, updated_at
FROM user_permission_grants
WHERE user_id = $1 AND permission = $2
`

// GetUserPermissionGrant 按用户与完整权限值查询直接授权；不存在时返回 (nil, nil)。
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
		return nil, errs.CreatePGError(err, "权限授权", "Failed to get user permission grant")
	}
	return &g, nil
}

// countUserPermissionGrantsSQL 统计某用户的全部直接授权数量。
const countUserPermissionGrantsSQL = `
SELECT count(*) FROM user_permission_grants WHERE user_id = $1
`

// listUserPermissionGrantsSQL 分页列出某用户的全部直接授权，按 id 倒序。
const listUserPermissionGrantsSQL = `
SELECT id, user_id, permission, granted_by_user_id, granted_by_app_id,
       valid_from, valid_until, note, created_at, updated_at
FROM user_permission_grants
WHERE user_id = $1
ORDER BY id DESC
LIMIT $2 OFFSET $3
`

// ListUserPermissionGrants 分页查询某用户的全部直接授权，返回当前页数据与总数。
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
	if e := db.R.QueryRow(ctx, countUserPermissionGrantsSQL, userID).Scan(&count); e != nil {
		return nil, 0, errs.CreatePGError(e, "权限授权", "Failed to count permission grants")
	}

	rows, e := db.R.Query(ctx, listUserPermissionGrantsSQL, userID, limit, offset)
	if e != nil {
		return nil, 0, errs.CreatePGError(e, "权限授权", "Failed to query permission grants")
	}

	grants, err := collectUserPermissionGrants(rows, "权限授权列表")
	if err != nil {
		return nil, 0, err
	}
	return grants, count, nil
}

// collectUserPermissionGrants 把查询结果收集为授权列表并关闭 rows；item 用于构造错误详情。
func collectUserPermissionGrants(rows pgx.Rows, item string) ([]*model.UserPermissionGrant, *errs.Error) {
	defer rows.Close()

	grants := make([]*model.UserPermissionGrant, 0)
	for rows.Next() {
		var g model.UserPermissionGrant
		if err := rows.Scan(
			&g.ID, &g.UserID, &g.Permission, &g.GrantedByUserID, &g.GrantedByAppID,
			&g.ValidFrom, &g.ValidUntil, &g.Note, &g.CreatedAt, &g.UpdatedAt,
		); err != nil {
			return nil, errs.CreatePGError(err, item, "Failed to scan permission grant")
		}
		grants = append(grants, &g)
	}
	if err := rows.Err(); err != nil {
		return nil, errs.CreatePGError(err, item, "Failed to iterate permission grants")
	}
	return grants, nil
}

// ---------------------------------------------------------------------------
// 用户有效权限
//
// 有效权限 = 有效的用户组权限（含 permission_implies 递归）∪ 有效的直接授权。
// 两类来源都受 valid_from/valid_until 约束，且要求所属应用处于 active 且未软删除。
// ---------------------------------------------------------------------------

// listUserEffectivePermissionsSQL 汇总用户的有效组权限与有效直接授权，返回完整权限串。
const listUserEffectivePermissionsSQL = `
WITH RECURSIVE granted AS (
    SELECT rp.permission_id AS id
    FROM user_roles ur
    JOIN role_permissions rp ON rp.role_id = ur.role_id
    WHERE ur.user_id = $1
      AND (ur.valid_from  IS NULL OR ur.valid_from  <= now())
      AND (ur.valid_until IS NULL OR ur.valid_until >  now())
    UNION
    SELECT pd.id
    FROM user_permission_grants g
    JOIN apps a ON a.id = g.granted_by_app_id
        AND a.status = 'active' AND a.deleted_at IS NULL
    JOIN permission_defs pd ON pd.app_id = a.id
        AND g.permission = a.namespace || ':' || pd.value
    WHERE g.user_id = $1
      AND (g.valid_from  IS NULL OR g.valid_from  <= now())
      AND (g.valid_until IS NULL OR g.valid_until >  now())
),
expanded AS (
    SELECT id FROM granted
    UNION
    SELECT pi.implied_permission_id
    FROM permission_implies pi
    JOIN expanded e ON pi.permission_id = e.id
)
SELECT DISTINCT a.namespace || ':' || pd.value AS permission
FROM permission_defs pd
JOIN apps a ON a.id = pd.app_id
JOIN expanded e ON e.id = pd.id
WHERE a.status = 'active' AND a.deleted_at IS NULL
ORDER BY 1
`

// ListUserEffectivePermissions 解析用户当前生效的全部权限，返回字典序升序的完整权限串。
// 登录签发令牌与应用维度有效权限查询共用该逻辑。
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
