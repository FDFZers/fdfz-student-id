package userperm

import (
	"context"
	"errors"
	"fdfz-student-id/internal/service/search"

	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"

	"github.com/jackc/pgx/v5"
)

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
RETURNING id, app_id, name, note, is_public, created_at, updated_at
`

func CreateRole(ctx context.Context, r *model.Role) *errs.Error {
	if r == nil {
		return errs.BadRequestError().AppendDetails("参数不能为空", "创建用户组失败")
	}
	err := db.R.QueryRow(ctx, createRoleSQL, r.AppID, r.Name, r.Note, r.Public).
		Scan(&r.ID, &r.AppID, &r.Name, &r.Note, &r.Public, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return errs.CreatePGError(err, "用户组", "Failed to create role").
			AppendDetails("创建用户组失败")
	}
	return nil
}

const getRoleSQL = `
SELECT id, app_id, name, note, is_public, created_at, updated_at
FROM roles WHERE id = $1
`

func GetRole(ctx context.Context, id int64) (*model.Role, *errs.Error) {
	var r model.Role
	err := db.R.QueryRow(ctx, getRoleSQL, id).Scan(
		&r.ID, &r.AppID, &r.Name, &r.Note, &r.Public, &r.CreatedAt, &r.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, errs.CreatePGError(err, "用户组", "Failed to get role").
			AppendDetails("获取用户组失败")
	}
	return &r, nil
}

const countRolesSQL = `SELECT count(*) FROM roles WHERE app_id = $1`

const listRolesSQL = `
SELECT id, app_id, name, note, is_public, created_at, updated_at
FROM roles WHERE app_id = $1
ORDER BY id
LIMIT $2 OFFSET $3
`

const countRolesVisibleToAppSQL = `SELECT count(*) FROM roles WHERE app_id = $1 OR is_public`

const listRolesVisibleToAppSQL = `
SELECT id, app_id, name, note, is_public, created_at, updated_at
FROM roles
WHERE app_id = $1 OR is_public
ORDER BY (app_id <> $1), id
LIMIT $2 OFFSET $3
`

func ListRolesVisibleToApp(ctx context.Context, appID int64, limit, offset int32) ([]*model.Role, int32, *errs.Error) {
	limit, offset = search.NormalizePagination(limit, offset)

	var count int32
	if err := db.R.QueryRow(ctx, countRolesVisibleToAppSQL, appID).Scan(&count); err != nil {
		return nil, 0, errs.CreatePGError(err, "用户组", "Failed to count visible roles").
			AppendDetails("用户组列表获取失败")
	}

	rows, err := db.R.Query(ctx, listRolesVisibleToAppSQL, appID, limit, offset)
	if err != nil {
		return nil, 0, errs.CreatePGError(err, "用户组", "Failed to query visible roles").
			AppendDetails("用户组列表获取失败")
	}

	roles, e := collectRoles(rows, "用户组列表")
	if e != nil {
		return nil, 0, e
	}
	return roles, count, nil
}

const getRoleVisibleToAppSQL = `
SELECT id, app_id, name, note, is_public, created_at, updated_at
FROM roles
WHERE id = $1 AND (app_id = $2 OR is_public)
`

func GetRoleVisibleToApp(ctx context.Context, appID, roleID int64) (*model.Role, *errs.Error) {
	var r model.Role
	err := db.R.QueryRow(ctx, getRoleVisibleToAppSQL, roleID, appID).Scan(
		&r.ID, &r.AppID, &r.Name, &r.Note, &r.Public, &r.CreatedAt, &r.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, errs.CreatePGError(err, "用户组", "Failed to get visible role").
			AppendDetails("获取用户组失败")
	}
	return &r, nil
}

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
	if err := db.R.QueryRow(ctx, countRolesSQL, appID).Scan(&count); err != nil {
		return nil, 0, errs.CreatePGError(err, "用户组", "Failed to count roles").
			AppendDetails("用户组列表获取失败")
	}

	rows, err := db.R.Query(ctx, listRolesSQL, appID, limit, offset)
	if err != nil {
		return nil, 0, errs.CreatePGError(err, "用户组", "Failed to query roles").
			AppendDetails("用户组列表获取失败")
	}

	roles, e := collectRoles(rows, "用户组列表")
	if e != nil {
		return nil, 0, e
	}
	return roles, count, nil
}

func collectRoles(rows pgx.Rows, item string) ([]*model.Role, *errs.Error) {
	defer rows.Close()

	roles := make([]*model.Role, 0)
	for rows.Next() {
		var r model.Role
		if err := rows.Scan(&r.ID, &r.AppID, &r.Name, &r.Note, &r.Public, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, errs.CreatePGError(err, item, "Failed to scan role").
				AppendDetails(item + "获取失败")
		}
		roles = append(roles, &r)
	}
	if err := rows.Err(); err != nil {
		return nil, errs.CreatePGError(err, item, "Failed to iterate roles").
			AppendDetails(item + "获取失败")
	}
	return roles, nil
}

const updateRoleSQL = `UPDATE roles SET name = $2, note = $3, is_public = $4 WHERE id = $1`

func UpdateRole(ctx context.Context, id int64, name, note string, public bool) *errs.Error {
	if _, err := db.R.Exec(ctx, updateRoleSQL, id, name, note, public); err != nil {
		return errs.CreatePGError(err, "用户组", "Failed to update role").
			AppendDetails("更新用户组失败")
	}
	return nil
}

const deleteRoleSQL = `DELETE FROM roles WHERE id = $1`

func DeleteRole(ctx context.Context, id int64) *errs.Error {
	if _, err := db.R.Exec(ctx, deleteRoleSQL, id); err != nil {
		return errs.CreatePGError(err, "用户组", "Failed to delete role").
			AppendDetails("删除用户组失败")
	}
	return nil
}

// ---------------------------------------------------------------------------
// 用户组权限 role_permissions
// ---------------------------------------------------------------------------

const addRolePermissionSQL = `
INSERT INTO role_permissions (role_id, permission_id)
VALUES ($1, $2)
ON CONFLICT (role_id, permission_id) DO NOTHING
`

func AddRolePermission(ctx context.Context, roleID, permissionID int64) *errs.Error {
	if _, err := db.R.Exec(ctx, addRolePermissionSQL, roleID, permissionID); err != nil {
		return errs.CreatePGError(err, "用户组权限", "Failed to add role permission").
			AppendDetails("添加用户组权限失败")
	}
	return nil
}

const removeRolePermissionSQL = `
DELETE FROM role_permissions WHERE role_id = $1 AND permission_id = $2
`

func RemoveRolePermission(ctx context.Context, roleID, permissionID int64) *errs.Error {
	if _, err := db.R.Exec(ctx, removeRolePermissionSQL, roleID, permissionID); err != nil {
		return errs.CreatePGError(err, "用户组权限", "Failed to remove role permission").
			AppendDetails("移除用户组权限失败")
	}
	return nil
}

const listRolePermissionsSQL = `
SELECT pd.id, pd.app_id, pd.value, pd.description, pd.requestable,
       pd.created_by, pd.created_at, pd.updated_at
FROM role_permissions rp
JOIN permission_defs pd ON pd.id = rp.permission_id
WHERE rp.role_id = $1
ORDER BY pd.id
`

func ListRolePermissions(ctx context.Context, roleID int64) ([]*model.PermissionDef, *errs.Error) {
	rows, err := db.R.Query(ctx, listRolePermissionsSQL, roleID)
	if err != nil {
		return nil, errs.CreatePGError(err, "用户组权限", "Failed to query role permissions").
			AppendDetails("获取用户组权限失败")
	}
	return collectPermissionDefs(rows, "用户组权限")
}

// ---------------------------------------------------------------------------
// 用户所在用户组 user_roles
// ---------------------------------------------------------------------------

const grantUserRoleSQL = `
INSERT INTO user_roles (user_id, role_id, granted_by, valid_from, valid_until)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (user_id, role_id) DO UPDATE
SET granted_by  = EXCLUDED.granted_by,
    valid_from  = EXCLUDED.valid_from,
    valid_until = EXCLUDED.valid_until
`

func GrantUserRole(ctx context.Context, ur *model.UserRole) *errs.Error {
	if ur == nil {
		return errs.BadRequestError().AppendDetails("参数不能为空", "授予用户组失败")
	}
	if _, err := db.R.Exec(ctx, grantUserRoleSQL,
		ur.UserID, ur.RoleID, ur.GrantedBy, ur.ValidFrom, ur.ValidUntil,
	); err != nil {
		return errs.CreatePGError(err, "用户所在用户组", "Failed to grant user role").
			AppendDetails("授予用户组失败")
	}
	return nil
}

const revokeUserRoleSQL = `DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2`

func RevokeUserRole(ctx context.Context, userID, roleID int64) *errs.Error {
	if _, err := db.R.Exec(ctx, revokeUserRoleSQL, userID, roleID); err != nil {
		return errs.CreatePGError(err, "用户所在用户组", "Failed to revoke user role").
			AppendDetails("撤销用户组失败")
	}
	return nil
}

// appID 传 nil 时返回该用户在所有应用下的有效用户组；不传 nil 时仅返回指定应用的。
const listUserRolesSQL = `
SELECT r.id, r.app_id, r.name, r.note, r.created_at, r.updated_at
FROM user_roles ur
JOIN roles r ON r.id = ur.role_id
WHERE ur.user_id = $1
  AND ($2::bigint IS NULL OR r.app_id = $2)
  AND (ur.valid_from  IS NULL OR ur.valid_from  <= now())
  AND (ur.valid_until IS NULL OR ur.valid_until >  now())
ORDER BY r.id
`

func ListUserRoles(ctx context.Context, userID int64, appID *int64) ([]*model.Role, *errs.Error) {
	rows, err := db.R.Query(ctx, listUserRolesSQL, userID, appID)
	if err != nil {
		return nil, errs.CreatePGError(err, "用户所在用户组", "Failed to query user roles").
			AppendDetails("用户所在用户组获取失败")
	}
	return collectRoles(rows, "用户所在用户组")
}

const countRoleUsersSQL = `SELECT count(*) FROM user_roles WHERE role_id = $1`

const listRoleUserIDsSQL = `
SELECT user_id
FROM user_roles
WHERE role_id = $1
ORDER BY created_at DESC, user_id DESC
LIMIT $2 OFFSET $3
`

// 返回拥有该用户组的用户 ID 列表（分页），如需要完整用户信息可在此基础上再做 JOIN。
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
		return nil, 0, errs.CreatePGError(err, "用户组成员", "Failed to count role users").
			AppendDetails("用户组成员列表获取失败")
	}

	rows, err := db.R.Query(ctx, listRoleUserIDsSQL, roleID, limit, offset)
	if err != nil {
		return nil, 0, errs.CreatePGError(err, "用户组成员", "Failed to query role users").
			AppendDetails("用户组成员列表获取失败")
	}
	defer rows.Close()

	ids := make([]int64, 0)
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, 0, errs.CreatePGError(err, "用户组成员", "Failed to scan role user").
				AppendDetails("用户组成员列表获取失败")
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, errs.CreatePGError(err, "用户组成员", "Failed to iterate role users").
			AppendDetails("用户组成员列表获取失败")
	}
	return ids, count, nil
}
