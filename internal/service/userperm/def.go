package userperm

import (
	"context"
	"errors"
	searchsvc "fdfz-student-id/internal/service/search"

	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	permsvc "fdfz-student-id/internal/service/perm"

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
	permsvc.NotifyReload()
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
		limit = searchsvc.DefaultLimit
	}
	if limit > searchsvc.MaxLimit {
		limit = searchsvc.MaxLimit
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
	permsvc.NotifyReload()
	return nil
}

// deletePermissionDefSQL 删除权限定义；继承边由外键级联清理，组权限模式保留（可能匹配重建的同名权限）。
const deletePermissionDefSQL = `DELETE FROM permission_defs WHERE id = $1`

const getPermissionDefForDeleteSQL = `
SELECT a.namespace, d.value
FROM permission_defs d
JOIN apps a ON a.id = d.app_id
WHERE d.id = $1
`

// user_permission_grants.permission 是纯文本且无外键，删除定义时须一并清理，否则重建同名权限会复活旧授权。
const deletePermissionGrantsByValueSQL = `
DELETE FROM user_permission_grants
WHERE permission = $1
`

const scrubAuthorizationPermissionSQL = `
UPDATE oauth_authorizations
SET permissions = COALESCE(
    (
        SELECT array_agg(p)
        FROM unnest(permissions) AS t(p)
        WHERE p <> $1
    ),
    '{}'
)
WHERE $1 = ANY(permissions)
`

// DeletePermissionDef 删除权限定义，并在同一事务内清理直接授权与 OAuth 授权数组。
func DeletePermissionDef(ctx context.Context, id int64) *errs.Error {
	tx, err := db.R.Begin(ctx)
	if err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to begin transaction for deleting permission def")
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var (
		namespace string
		value     string
	)
	if err := tx.QueryRow(ctx, getPermissionDefForDeleteSQL, id).Scan(&namespace, &value); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errs.NotFoundError().AppendDetails("权限定义不存在")
		}
		return errs.CreatePGError(err, "权限定义", "Failed to load permission def before delete")
	}

	fullPermission := permsvc.Render(namespace, value)
	if _, err := tx.Exec(ctx, deletePermissionGrantsByValueSQL, fullPermission); err != nil {
		return errs.CreatePGError(err, "权限定义", "Failed to delete permission grants")
	}
	if _, err := tx.Exec(ctx, scrubAuthorizationPermissionSQL, fullPermission); err != nil {
		return errs.CreatePGError(err, "权限定义", "Failed to scrub oauth authorizations")
	}
	if _, err := tx.Exec(ctx, deletePermissionDefSQL, id); err != nil {
		return errs.CreatePGError(err, "权限定义", "Failed to delete permission def")
	}
	if err := tx.Commit(ctx); err != nil {
		return errs.CreateAndLogInternalError(err, "Failed to commit permission def deletion")
	}

	permsvc.NotifyReload()
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

	direct, err := ListDirectImplications(ctx, permissionID)
	if err != nil {
		return err
	}
	implications := make([]*model.PermissionImply, 0, len(direct)+1)
	implications = append(implications, direct...)
	implications = append(implications, &model.PermissionImply{ImpliedPermissionID: impliedID})

	return SetPermissionImplies(ctx, db.R, def.AppID, permissionID, implications)
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

	direct, err := ListDirectImplications(ctx, permissionID)
	if err != nil {
		return err
	}
	implications := make([]*model.PermissionImply, 0, len(direct))
	for _, implication := range direct {
		if implication.ImpliedPermissionID != impliedID {
			implications = append(implications, implication)
		}
	}

	return SetPermissionImplies(ctx, db.R, def.AppID, permissionID, implications)
}

const listDirectImplicationsSQL = `
SELECT permission_id, implied_permission_id, granted_by_user_id,
       valid_from, valid_until, note, created_at, updated_at
FROM permission_implies
WHERE permission_id = $1
ORDER BY implied_permission_id
`

func ListDirectImplications(ctx context.Context, permissionID int64) ([]*model.PermissionImply, *errs.Error) {
	rows, err := db.R.Query(ctx, listDirectImplicationsSQL, permissionID)
	if err != nil {
		return nil, errs.CreatePGError(err, "权限继承", "Failed to query permission implies")
	}
	defer rows.Close()

	implications := make([]*model.PermissionImply, 0)
	for rows.Next() {
		var implication model.PermissionImply
		if err := rows.Scan(
			&implication.PermissionID, &implication.ImpliedPermissionID, &implication.GrantedByUserID,
			&implication.ValidFrom, &implication.ValidUntil, &implication.Note,
			&implication.CreatedAt, &implication.UpdatedAt,
		); err != nil {
			return nil, errs.CreatePGError(err, "权限继承", "Failed to scan permission implication")
		}
		implications = append(implications, &implication)
	}
	if err := rows.Err(); err != nil {
		return nil, errs.CreatePGError(err, "权限继承", "Failed to iterate permission implications")
	}
	return implications, nil
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
