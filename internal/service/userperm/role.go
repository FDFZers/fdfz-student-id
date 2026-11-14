package userperm

import (
	"context"
	"errors"
	searchsvc "fdfz-student-id/internal/service/search"

	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"

	"github.com/jackc/pgx/v5"
)

// 用户组列表的分页限制。
const (
	RoleListDefaultLimit int32 = 20
	RoleListMaxLimit     int32 = 100
)

// ---------------------------------------------------------------------------
// 用户组 CRUD
// ---------------------------------------------------------------------------

const createRoleSQL = `
INSERT INTO roles (app_id, name, note, is_public)
VALUES ($1, $2, $3, $4)
RETURNING id, app_id, name, note, is_public, is_system, created_at, updated_at
`

// CreateRole 新建用户组并回填 id；同应用下名称唯一由数据库唯一约束保证（冲突时返回 conflict）。
func CreateRole(ctx context.Context, r *model.Role) *errs.Error {
	if r == nil {
		return errs.BadRequestError().AppendDetails("未提供参数")
	}
	err := db.R.QueryRow(ctx, createRoleSQL, r.AppID, r.Name, r.Note, r.Public).
		Scan(&r.ID, &r.AppID, &r.Name, &r.Note, &r.Public, &r.System, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return errs.CreatePGError(err, "用户组", "Failed to create role")
	}
	return nil
}

// getRoleSQL 按 id 查询用户组。
const getRoleSQL = `
SELECT id, app_id, name, note, is_public, is_system, created_at, updated_at
FROM roles WHERE id = $1
`

// GetRole 按 id 查询用户组；不存在时返回 (nil, nil)。
func GetRole(ctx context.Context, id int64) (*model.Role, *errs.Error) {
	var r model.Role
	err := db.R.QueryRow(ctx, getRoleSQL, id).Scan(
		&r.ID, &r.AppID, &r.Name, &r.Note, &r.Public, &r.System, &r.CreatedAt, &r.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, errs.CreatePGError(err, "用户组", "Failed to get role")
	}
	return &r, nil
}

// countRolesSQL 统计某应用下的用户组数量。
const countRolesSQL = `SELECT count(*) FROM roles WHERE app_id = $1`

// listRolesSQL 分页列出某应用下的全部用户组（不区分是否公开）。
const listRolesSQL = `
SELECT id, app_id, name, note, is_public, is_system, created_at, updated_at
FROM roles WHERE app_id = $1
ORDER BY id
LIMIT $2 OFFSET $3
`

// countRolesVisibleToAppSQL 统计对某应用可见的用户组数量（本应用 ∪ 其他应用的公开组）。
// 其他应用的公开组仅在来源应用 active 且未软删除时可见。
const countRolesVisibleToAppSQL = `
SELECT count(*)
FROM roles r
JOIN apps a ON a.id = r.app_id
WHERE r.app_id = $1 OR (r.is_public AND a.status = 'active' AND a.deleted_at IS NULL)
`

// listRolesVisibleToAppSQL 分页列出对某应用可见的用户组，本应用的组排在前面。
const listRolesVisibleToAppSQL = `
SELECT r.id, r.app_id, r.name, r.note, r.is_public, r.is_system, r.created_at, r.updated_at
FROM roles r
JOIN apps a ON a.id = r.app_id
WHERE r.app_id = $1 OR (r.is_public AND a.status = 'active' AND a.deleted_at IS NULL)
ORDER BY (r.app_id <> $1), r.id
LIMIT $2 OFFSET $3
`

// ListRolesVisibleToApp 分页查询对某应用可见的用户组（本应用 ∪ 其他应用的公开组），返回当前页与总数。
func ListRolesVisibleToApp(ctx context.Context, appID int64, limit, offset int32) ([]*model.Role, int32, *errs.Error) {
	limit, offset = searchsvc.NormalizePagination(limit, offset)

	var count int32
	if e := db.R.QueryRow(ctx, countRolesVisibleToAppSQL, appID).Scan(&count); e != nil {
		return nil, 0, errs.CreatePGError(e, "用户组", "Failed to count visible roles")
	}

	rows, e := db.R.Query(ctx, listRolesVisibleToAppSQL, appID, limit, offset)
	if e != nil {
		return nil, 0, errs.CreatePGError(e, "用户组", "Failed to query visible roles")
	}

	roles, err := collectRoles(rows, "用户组列表")
	if err != nil {
		return nil, 0, err
	}
	return roles, count, nil
}

// getRoleVisibleToAppSQL 按可见性查询用户组：本应用的组或其他应用（active 且未软删除）的公开组。
const getRoleVisibleToAppSQL = `
SELECT r.id, r.app_id, r.name, r.note, r.is_public, r.is_system, r.created_at, r.updated_at
FROM roles r
JOIN apps a ON a.id = r.app_id
WHERE r.id = $1 AND (r.app_id = $2 OR (r.is_public AND a.status = 'active' AND a.deleted_at IS NULL))
`

// GetRoleVisibleToApp 按可见性查询用户组；不可见时返回 (nil, nil)。
func GetRoleVisibleToApp(ctx context.Context, appID, roleID int64) (*model.Role, *errs.Error) {
	var r model.Role
	err := db.R.QueryRow(ctx, getRoleVisibleToAppSQL, roleID, appID).Scan(
		&r.ID, &r.AppID, &r.Name, &r.Note, &r.Public, &r.System, &r.CreatedAt, &r.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, errs.CreatePGError(err, "用户组", "Failed to get visible role")
	}
	return &r, nil
}

// ListRoles 分页查询某应用下的全部用户组（不区分是否公开），返回当前页与总数。
func ListRoles(ctx context.Context, appID int64, limit, offset int32) ([]*model.Role, int32, *errs.Error) {
	if limit <= 0 {
		limit = RoleListDefaultLimit
	}
	if limit > RoleListMaxLimit {
		limit = RoleListMaxLimit
	}
	if offset < 0 {
		offset = 0
	}

	var count int32
	if e := db.R.QueryRow(ctx, countRolesSQL, appID).Scan(&count); e != nil {
		return nil, 0, errs.CreatePGError(e, "用户组", "Failed to count roles")
	}

	rows, e := db.R.Query(ctx, listRolesSQL, appID, limit, offset)
	if e != nil {
		return nil, 0, errs.CreatePGError(e, "用户组", "Failed to query roles")
	}

	roles, err := collectRoles(rows, "用户组列表")
	if err != nil {
		return nil, 0, err
	}
	return roles, count, nil
}

// collectRoles 把查询结果收集为用户组列表并关闭 rows；item 用于构造错误详情。
func collectRoles(rows pgx.Rows, item string) ([]*model.Role, *errs.Error) {
	defer rows.Close()

	roles := make([]*model.Role, 0)
	for rows.Next() {
		var r model.Role
		if err := rows.Scan(&r.ID, &r.AppID, &r.Name, &r.Note, &r.Public, &r.System, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, errs.CreatePGError(err, item, "Failed to scan role")
		}
		roles = append(roles, &r)
	}
	if err := rows.Err(); err != nil {
		return nil, errs.CreatePGError(err, item, "Failed to iterate roles")
	}
	return roles, nil
}

// updateRoleSQL 更新用户组名称、备注与公开标记；系统用户组不可改名。
const updateRoleSQL = `
UPDATE roles
SET name = $2, note = $3, is_public = $4
WHERE id = $1 AND (is_system = false OR name = $2)
`

// UpdateRole 更新用户组名称、备注与公开标记；名称冲突由数据库唯一约束返回 conflict。
func UpdateRole(ctx context.Context, id int64, name, note string, public bool) *errs.Error {
	if _, err := db.R.Exec(ctx, updateRoleSQL, id, name, note, public); err != nil {
		return errs.CreatePGError(err, "用户组", "Failed to update role")
	}
	return nil
}

const deleteRoleSQL = `DELETE FROM roles WHERE id = $1 AND is_system = false`

// DeleteRole 删除用户组；不存在的 id 与系统用户组都视为未删除并返回成功。
func DeleteRole(ctx context.Context, id int64) *errs.Error {
	if _, err := db.R.Exec(ctx, deleteRoleSQL, id); err != nil {
		return errs.CreatePGError(err, "用户组", "Failed to delete role")
	}
	return nil
}

// ---------------------------------------------------------------------------
// 用户组权限 role_permissions
// ---------------------------------------------------------------------------

const listRolePermissionsSQL = `
SELECT role_id, permission, granted_by_user_id, valid_from, valid_until, note, created_at, updated_at
FROM role_permissions
WHERE role_id = $1
ORDER BY permission
`

// ListRolePermissions 列出用户组直接拥有的权限模式与授权记录。
// 不展开权限继承，展开由 perm.ResolvePatterns 在鉴权时完成。
func ListRolePermissions(ctx context.Context, roleID int64) ([]*model.RolePermission, *errs.Error) {
	rows, err := db.R.Query(ctx, listRolePermissionsSQL, roleID)
	if err != nil {
		return nil, errs.CreatePGError(err, "用户组权限", "Failed to query role permissions")
	}
	defer rows.Close()

	grants := make([]*model.RolePermission, 0)
	for rows.Next() {
		var grant model.RolePermission
		if err := rows.Scan(
			&grant.RoleID, &grant.Permission, &grant.GrantedByUserID,
			&grant.ValidFrom, &grant.ValidUntil, &grant.Note,
			&grant.CreatedAt, &grant.UpdatedAt,
		); err != nil {
			return nil, errs.CreatePGError(err, "用户组权限", "Failed to scan role permission")
		}
		grants = append(grants, &grant)
	}
	if err := rows.Err(); err != nil {
		return nil, errs.CreatePGError(err, "用户组权限", "Failed to iterate role permissions")
	}
	return grants, nil
}

// ---------------------------------------------------------------------------
// 用户所在用户组 user_roles
// ---------------------------------------------------------------------------

// grantUserRoleSQL 写入用户组成员关系；重复授予时覆盖授予人与有效期。
const grantUserRoleSQL = `
INSERT INTO user_roles (user_id, role_id, granted_by, valid_from, valid_until)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (user_id, role_id) DO UPDATE
SET granted_by  = EXCLUDED.granted_by,
    valid_from  = EXCLUDED.valid_from,
    valid_until = EXCLUDED.valid_until
`

// GrantUserRole 授予用户组给用户（按 user_id + role_id upsert）；有效期由 valid_from/valid_until 控制。
func GrantUserRole(ctx context.Context, ur *model.UserRole) *errs.Error {
	if ur == nil {
		return errs.BadRequestError().AppendDetails("未提供参数")
	}
	if _, err := db.R.Exec(ctx, grantUserRoleSQL,
		ur.UserID, ur.RoleID, ur.GrantedBy, ur.ValidFrom, ur.ValidUntil,
	); err != nil {
		return errs.CreatePGError(err, "用户所在用户组", "Failed to grant user role")
	}
	return nil
}

// revokeUserRoleSQL 删除用户与用户组的成员关系。
const revokeUserRoleSQL = `DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2`

// RevokeUserRole 撤销用户组成员关系；不存在时幂等成功。
func RevokeUserRole(ctx context.Context, userID, roleID int64) *errs.Error {
	if _, err := db.R.Exec(ctx, revokeUserRoleSQL, userID, roleID); err != nil {
		return errs.CreatePGError(err, "用户所在用户组", "Failed to revoke user role")
	}
	return nil
}

// listUserRolesSQL 查询用户当前有效的用户组；appID 为 nil 时返回所有应用，否则仅返回指定应用。
// 查询列必须与 collectRoles 的 Scan 参数完全一致（含 is_public、is_system）。
const listUserRolesSQL = `
SELECT r.id, r.app_id, r.name, r.note, r.is_public, r.is_system, r.created_at, r.updated_at
FROM user_roles ur
JOIN roles r ON r.id = ur.role_id
WHERE ur.user_id = $1
  AND ($2::bigint IS NULL OR r.app_id = $2)
  AND (ur.valid_from  IS NULL OR ur.valid_from  <= now())
  AND (ur.valid_until IS NULL OR ur.valid_until >  now())
ORDER BY r.id
`

// ListUserRoles 查询用户当前有效的用户组，可按应用过滤（appID 为 nil 表示不限应用）。
func ListUserRoles(ctx context.Context, userID int64, appID *int64) ([]*model.Role, *errs.Error) {
	rows, err := db.R.Query(ctx, listUserRolesSQL, userID, appID)
	if err != nil {
		return nil, errs.CreatePGError(err, "用户所在用户组", "Failed to query user roles")
	}
	return collectRoles(rows, "用户所在用户组")
}

// countRoleUsersSQL 统计某用户组的成员数量。
const countRoleUsersSQL = `SELECT count(*) FROM user_roles WHERE role_id = $1`

// listRoleUserIDsSQL 分页列出某用户组的成员用户 ID，按加入时间倒序。
const listRoleUserIDsSQL = `
SELECT user_id
FROM user_roles
WHERE role_id = $1
ORDER BY created_at DESC, user_id DESC
LIMIT $2 OFFSET $3
`

// ListRoleUserIDs 分页查询某用户组的成员用户 ID；需要完整用户信息时可在此基础上再 JOIN。
func ListRoleUserIDs(ctx context.Context, roleID int64, limit, offset int32) ([]int64, int32, *errs.Error) {
	if limit <= 0 {
		limit = RoleListDefaultLimit
	}
	if limit > RoleListMaxLimit {
		limit = RoleListMaxLimit
	}
	if offset < 0 {
		offset = 0
	}

	var count int32
	if err := db.R.QueryRow(ctx, countRoleUsersSQL, roleID).Scan(&count); err != nil {
		return nil, 0, errs.CreatePGError(err, "用户组成员", "Failed to count role users")
	}

	rows, err := db.R.Query(ctx, listRoleUserIDsSQL, roleID, limit, offset)
	if err != nil {
		return nil, 0, errs.CreatePGError(err, "用户组成员", "Failed to query role users")
	}
	defer rows.Close()

	ids := make([]int64, 0)
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, 0, errs.CreatePGError(err, "用户组成员", "Failed to scan role user")
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, errs.CreatePGError(err, "用户组成员", "Failed to iterate role users")
	}
	return ids, count, nil
}
