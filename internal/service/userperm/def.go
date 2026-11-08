// Package userperm 实现用户组（Role）、用户组成员、组权限与用户直接授权的数据库读写，
// 以及用户有效权限和权限值的解析。
package userperm

import (
	"context"
	"errors"
	"fdfz-student-id/internal/service/search"

	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/service/perm"

	"github.com/jackc/pgx/v5"
)

// ---------------------------------------------------------------------------
// 权限定义 CRUD
// ---------------------------------------------------------------------------

// createPermissionDefSQL 新建权限定义并回填自增 id 与时间戳。
const createPermissionDefSQL = `
INSERT INTO permission_defs (app_id, value, description, requestable, created_by)
VALUES ($1, $2, $3, $4, $5)
RETURNING id, app_id, value, description, requestable, created_by, created_at, updated_at
`

// CreatePermissionDef 新建一条权限定义；成功后触发权限目录异步重载。
func CreatePermissionDef(ctx context.Context, def *model.PermissionDef) *errs.Error {
	if def == nil {
		return errs.BadRequestError().AppendDetails("未提供参数")
	}
	err := db.R.QueryRow(ctx, createPermissionDefSQL,
		def.AppID, def.Value, def.Description, def.Requestable, def.CreatedBy,
	).Scan(
		&def.ID, &def.AppID, &def.Value, &def.Description, &def.Requestable,
		&def.CreatedBy, &def.CreatedAt, &def.UpdatedAt,
	)
	if err != nil {
		return errs.CreatePGError(err, "权限定义", "Failed to create permission def")
	}
	perm.NotifyReload()
	return nil
}

// getPermissionDefSQL 按 id 查询单条权限定义。
const getPermissionDefSQL = `
SELECT id, app_id, value, description, requestable, created_by, created_at, updated_at
FROM permission_defs
WHERE id = $1
`

// GetPermissionDef 按 id 查询权限定义；不存在时返回 (nil, nil)。
func GetPermissionDef(ctx context.Context, id int64) (*model.PermissionDef, *errs.Error) {
	var d model.PermissionDef
	err := db.R.QueryRow(ctx, getPermissionDefSQL, id).Scan(
		&d.ID, &d.AppID, &d.Value, &d.Description, &d.Requestable,
		&d.CreatedBy, &d.CreatedAt, &d.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, errs.CreatePGError(err, "权限定义", "Failed to get permission def")
	}
	return &d, nil
}

// getPermissionDefIDByValueSQL 按应用与权限值（不含命名空间）查询权限定义 id。
const getPermissionDefIDByValueSQL = `
SELECT id FROM permission_defs WHERE app_id = $1 AND value = $2
`

// GetPermissionDefIDByValue 按应用与权限值查询权限定义 id；不存在时返回 (0, nil)。
func GetPermissionDefIDByValue(ctx context.Context, appID int64, value string) (int64, *errs.Error) {
	var id int64
	err := db.R.QueryRow(ctx, getPermissionDefIDByValueSQL, appID, value).Scan(&id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, nil
		}
		return 0, errs.CreatePGError(err, "权限定义", "Failed to lookup permission def")
	}
	return id, nil
}

// countPermissionDefsSQL 统计某应用下的权限定义数量。
const countPermissionDefsSQL = `SELECT count(*) FROM permission_defs WHERE app_id = $1`

// listPermissionDefsSQL 分页列出某应用下的权限定义，按 id 升序。
const listPermissionDefsSQL = `
SELECT id, app_id, value, description, requestable, created_by, created_at, updated_at
FROM permission_defs
WHERE app_id = $1
ORDER BY id
LIMIT $2 OFFSET $3
`

// ListPermissionDefs 分页查询某应用下的权限定义，返回当前页数据与总数。
func ListPermissionDefs(ctx context.Context, appID int64, limit, offset int32) ([]*model.PermissionDef, int32, *errs.Error) {
	if limit <= 0 {
		limit = search.DefaultLimit
	}
	if limit > search.MaxLimit {
		limit = search.MaxLimit
	}
	if offset < 0 {
		offset = 0
	}

	var count int32
	if e := db.R.QueryRow(ctx, countPermissionDefsSQL, appID).Scan(&count); e != nil {
		return nil, 0, errs.CreatePGError(e, "权限定义", "Failed to count permission defs")
	}

	rows, e := db.R.Query(ctx, listPermissionDefsSQL, appID, limit, offset)
	if e != nil {
		return nil, 0, errs.CreatePGError(e, "权限定义", "Failed to query permission defs")
	}

	defs, err := collectPermissionDefs(rows, "权限定义列表")
	if err != nil {
		return nil, 0, err
	}
	return defs, count, nil
}

// collectPermissionDefs 把查询结果收集为权限定义列表并关闭 rows；item 用于构造错误详情。
func collectPermissionDefs(rows pgx.Rows, item string) ([]*model.PermissionDef, *errs.Error) {
	defer rows.Close()

	defs := make([]*model.PermissionDef, 0)
	for rows.Next() {
		var d model.PermissionDef
		if err := rows.Scan(
			&d.ID, &d.AppID, &d.Value, &d.Description, &d.Requestable,
			&d.CreatedBy, &d.CreatedAt, &d.UpdatedAt,
		); err != nil {
			return nil, errs.CreatePGError(err, item, "Failed to scan permission def")
		}
		defs = append(defs, &d)
	}
	if err := rows.Err(); err != nil {
		return nil, errs.CreatePGError(err, item, "Failed to iterate permission defs")
	}
	return defs, nil
}

// updatePermissionDefSQL 更新权限定义的描述与「可申请」标记；权限值不可修改。
const updatePermissionDefSQL = `
UPDATE permission_defs
SET description = $2, requestable = $3
WHERE id = $1
`

// UpdatePermissionDef 更新权限定义的描述与「可申请」标记；成功后触发权限目录异步重载。
func UpdatePermissionDef(ctx context.Context, id int64, description string, requestable bool) *errs.Error {
	if _, err := db.R.Exec(ctx, updatePermissionDefSQL, id, description, requestable); err != nil {
		return errs.CreatePGError(err, "权限定义", "Failed to update permission def")
	}
	perm.NotifyReload()
	return nil
}

// deletePermissionDefSQL 删除权限定义，关联的组权限与继承边由外键级联清理。
const deletePermissionDefSQL = `DELETE FROM permission_defs WHERE id = $1`

// DeletePermissionDef 删除权限定义；成功后触发权限目录异步重载。
func DeletePermissionDef(ctx context.Context, id int64) *errs.Error {
	if _, err := db.R.Exec(ctx, deletePermissionDefSQL, id); err != nil {
		return errs.CreatePGError(err, "权限定义", "Failed to delete permission def")
	}
	perm.NotifyReload()
	return nil
}

// ---------------------------------------------------------------------------
// 权限继承 permission_implies
//
// 注意：写操作统一走 manage.go 中的 SetPermissionImplies，以复用应用归属校验、
// 应用级 advisory lock 与循环依赖检测。以下两个辅助函数只是在其上的便捷封装。
// ---------------------------------------------------------------------------

// AddPermissionImply 在保留现有直接继承关系的前提下追加一条继承边。
func AddPermissionImply(ctx context.Context, permissionID, impliedID int64) *errs.Error {
	def, err := GetPermissionDef(ctx, permissionID)
	if err != nil {
		return err
	}
	if def == nil {
		return errs.NotFoundError().AppendDetails("权限定义不存在")
	}

	direct, err := ListDirectImpliedPermissions(ctx, permissionID)
	if err != nil {
		return err
	}
	ids := make([]int64, 0, len(direct)+1)
	for _, item := range direct {
		ids = append(ids, item.ID)
	}
	ids = append(ids, impliedID)

	return SetPermissionImplies(ctx, def.AppID, permissionID, ids)
}

// RemovePermissionImply 移除一条直接继承边（不存在时幂等成功）。
func RemovePermissionImply(ctx context.Context, permissionID, impliedID int64) *errs.Error {
	def, err := GetPermissionDef(ctx, permissionID)
	if err != nil {
		return err
	}
	if def == nil {
		return errs.NotFoundError().AppendDetails("权限定义不存在")
	}

	direct, err := ListDirectImpliedPermissions(ctx, permissionID)
	if err != nil {
		return err
	}
	ids := make([]int64, 0, len(direct))
	for _, item := range direct {
		if item.ID != impliedID {
			ids = append(ids, item.ID)
		}
	}

	return SetPermissionImplies(ctx, def.AppID, permissionID, ids)
}

// listDirectImpliesSQL 查询某权限直接继承的权限定义。
const listDirectImpliesSQL = `
SELECT pd.id, pd.app_id, pd.value, pd.description, pd.requestable,
       pd.created_by, pd.created_at, pd.updated_at
FROM permission_implies pi
JOIN permission_defs pd ON pd.id = pi.implied_permission_id
WHERE pi.permission_id = $1
ORDER BY pd.id
`

// ListDirectImpliedPermissions 列出某权限直接继承的权限定义（不含传递闭包）。
func ListDirectImpliedPermissions(ctx context.Context, permissionID int64) ([]*model.PermissionDef, *errs.Error) {
	rows, err := db.R.Query(ctx, listDirectImpliesSQL, permissionID)
	if err != nil {
		return nil, errs.CreatePGError(err, "权限继承", "Failed to query permission implies")
	}
	return collectPermissionDefs(rows, "权限继承")
}

// listImpliedPermissionsRecursiveSQL 递归展开全部继承关系，用于审计与调试。
const listImpliedPermissionsRecursiveSQL = `
WITH RECURSIVE implied AS (
    SELECT implied_permission_id AS id
    FROM permission_implies
    WHERE permission_id = $1
    UNION
    SELECT pi.implied_permission_id
    FROM permission_implies pi
    JOIN implied i ON pi.permission_id = i.id
)
SELECT pd.id, pd.app_id, pd.value, pd.description, pd.requestable,
       pd.created_by, pd.created_at, pd.updated_at
FROM permission_defs pd
JOIN implied i ON i.id = pd.id
ORDER BY pd.id
`

// ListImpliedPermissions 递归展开某权限继承的全部权限定义，仅用于审计与调试。
// 注意：运行时鉴权使用权限目录中的继承图递归展开，不读取该查询结果。
func ListImpliedPermissions(ctx context.Context, permissionID int64) ([]*model.PermissionDef, *errs.Error) {
	rows, err := db.R.Query(ctx, listImpliedPermissionsRecursiveSQL, permissionID)
	if err != nil {
		return nil, errs.CreatePGError(err, "权限继承", "Failed to query implied permissions")
	}
	return collectPermissionDefs(rows, "权限继承")
}
