package userperm

import (
	"context"
	"errors"
	"fdfz-student-id/internal/service/search"
	"fmt"
	"strings"
	"time"

	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	appsvc "fdfz-student-id/internal/service/app"
	"fdfz-student-id/internal/service/perm"

	"github.com/guregu/null/v6"
	"github.com/jackc/pgx/v5"
)

// permissionDefColumns 权限定义的查询列，供拼接各条 SQL 使用。
const permissionDefColumns = `
id, app_id, value, description, requestable, created_by, created_at, updated_at
`

// appPermissionDefSQL 按「id + 应用」查询权限定义，用于应用维度的归属校验。
const appPermissionDefSQL = `
SELECT ` + permissionDefColumns + `
FROM permission_defs
WHERE id = $1 AND app_id = $2
`

// GetPermissionDefInApp 按应用归属查询权限定义；不存在或不属于该应用时返回 (nil, nil)。
func GetPermissionDefInApp(ctx context.Context, appID, permissionID int64) (*model.PermissionDef, *errs.Error) {
	var d model.PermissionDef
	err := db.R.QueryRow(ctx, appPermissionDefSQL, permissionID, appID).Scan(
		&d.ID, &d.AppID, &d.Value, &d.Description, &d.Requestable,
		&d.CreatedBy, &d.CreatedAt, &d.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, errs.CreatePGError(err, "权限定义", "Failed to get permission def in app")
	}
	return &d, nil
}

// appRoleSQL 按「id + 应用」查询用户组，用于应用维度的归属校验。
const appRoleSQL = `
SELECT id, app_id, name, note, is_public, created_at, updated_at
FROM roles
WHERE id = $1 AND app_id = $2
`

// GetRoleInApp 按应用归属查询用户组；不存在或不属于该应用时返回 (nil, nil)。
// 注意：应用维度需要“本应用 ∪ 公开用户组”的可见性判断时，请使用 GetRoleVisibleToApp。
func GetRoleInApp(ctx context.Context, appID, roleID int64) (*model.Role, *errs.Error) {
	var r model.Role
	err := db.R.QueryRow(ctx, appRoleSQL, roleID, appID).Scan(
		&r.ID, &r.AppID, &r.Name, &r.Note, &r.Public, &r.CreatedAt, &r.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, errs.CreatePGError(err, "用户组", "Failed to get role in app")
	}
	return &r, nil
}

// ---------------------------------------------------------------------------
// 全局列表
// ---------------------------------------------------------------------------

// countAllPermissionDefsSQL 统计权限定义数量；appID 为 nil 时统计全部应用。
const countAllPermissionDefsSQL = `
SELECT count(*) FROM permission_defs WHERE ($1::bigint IS NULL OR app_id = $1)
`

// listAllPermissionDefsSQL 分页列出权限定义；appID 为 nil 时跨应用查询。
const listAllPermissionDefsSQL = `
SELECT ` + permissionDefColumns + `
FROM permission_defs
WHERE ($1::bigint IS NULL OR app_id = $1)
ORDER BY id
LIMIT $2 OFFSET $3
`

// ListAllPermissionDefs 分页查询权限定义，appID 为 nil 时跨应用查询，返回当前页与总数。
func ListAllPermissionDefs(ctx context.Context, appID *int64, limit, offset int32) ([]*model.PermissionDef, int32, *errs.Error) {
	limit, offset = search.NormalizePagination(limit, offset)

	var count int32
	if e := db.R.QueryRow(ctx, countAllPermissionDefsSQL, appID).Scan(&count); e != nil {
		return nil, 0, errs.CreatePGError(e, "权限定义", "Failed to count permission defs")
	}

	rows, e := db.R.Query(ctx, listAllPermissionDefsSQL, appID, limit, offset)
	if e != nil {
		return nil, 0, errs.CreatePGError(e, "权限定义", "Failed to query permission defs")
	}

	defs, err := collectPermissionDefs(rows, "权限定义列表")
	if err != nil {
		return nil, 0, err
	}
	return defs, count, nil
}

// countAllRolesSQL 统计用户组数量；appID 为 nil 时统计全部应用。
const countAllRolesSQL = `SELECT count(*) FROM roles WHERE ($1::bigint IS NULL OR app_id = $1)`

// listAllRolesSQL 分页列出用户组；appID 为 nil 时跨应用查询。
const listAllRolesSQL = `
SELECT id, app_id, name, note, is_public, created_at, updated_at
FROM roles
WHERE ($1::bigint IS NULL OR app_id = $1)
ORDER BY id
LIMIT $2 OFFSET $3
`

// ListAllRoles 分页查询用户组，appID 为 nil 时跨应用查询，返回当前页与总数。
func ListAllRoles(ctx context.Context, appID *int64, limit, offset int32) ([]*model.Role, int32, *errs.Error) {
	limit, offset = search.NormalizePagination(limit, offset)

	var count int32
	if e := db.R.QueryRow(ctx, countAllRolesSQL, appID).Scan(&count); e != nil {
		return nil, 0, errs.CreatePGError(e, "用户组", "Failed to count roles")
	}

	rows, e := db.R.Query(ctx, listAllRolesSQL, appID, limit, offset)
	if e != nil {
		return nil, 0, errs.CreatePGError(e, "用户组", "Failed to query roles")
	}

	roles, err := collectRoles(rows, "用户组列表")
	if err != nil {
		return nil, 0, err
	}
	return roles, count, nil
}

// ---------------------------------------------------------------------------
// 完整权限串解析
// ---------------------------------------------------------------------------

// resolvePermissionValuesSQL 按应用与权限值批量查询权限定义。
const resolvePermissionValuesSQL = `
SELECT ` + permissionDefColumns + `
FROM permission_defs
WHERE app_id = $1 AND value = ANY($2::text[])
`

// parseFullPermission 解析「命名空间:节点...」形式的完整权限串并校验命名空间，
// 返回去掉命名空间、以 "." 连接的权限值。
func parseFullPermission(value, namespace string) (string, *errs.Error) {
	parsed, err := perm.ParsePermission(value)
	if err != nil {
		return "", errs.BadRequestError().AppendDetails(
			fmt.Sprintf("权限“%s”格式错误", value),
		)
	}
	if namespace != "" && parsed.Namespace != namespace {
		return "", errs.BadRequestError().AppendDetails(
			fmt.Sprintf("权限“%s”不属于该应用", value),
		)
	}
	return strings.Join(parsed.Nodes, "."), nil
}

// ResolvePermissionValues 把一批完整权限串解析为当前应用的权限定义列表，顺序与输入一致。
// 任一条目格式错误、不属于该应用或权限定义不存在时整体失败。
func ResolvePermissionValues(ctx context.Context, appID int64, namespace string, values []string) ([]*model.PermissionDef, *errs.Error) {
	// 解析完整权限串，去掉命名空间并校验归属应用。
	paths := make([]string, 0, len(values))
	for _, value := range values {
		path, err := parseFullPermission(value, namespace)
		if err != nil {
			return nil, err
		}
		paths = append(paths, path)
	}

	if len(paths) == 0 {
		return make([]*model.PermissionDef, 0), nil
	}

	// 批量查询定义，再按输入顺序回填并校验存在性。
	rows, e := db.R.Query(ctx, resolvePermissionValuesSQL, appID, paths)
	if e != nil {
		return nil, errs.CreatePGError(e, "权限定义", "Failed to query permission defs by values")
	}
	defs, err := collectPermissionDefs(rows, "权限定义")
	if err != nil {
		return nil, err
	}

	byValue := make(map[string]*model.PermissionDef, len(defs))
	for _, d := range defs {
		byValue[d.Value] = d
	}

	result := make([]*model.PermissionDef, 0, len(paths))
	for i, path := range paths {
		d, ok := byValue[path]
		if !ok {
			return nil, errs.NotFoundError().AppendDetails(
				fmt.Sprintf("权限“%s”不存在", values[i]),
			)
		}
		if d.AppID != appID {
			// 查询条件已限定 app_id，这里仅作防御性校验。
			return nil, errs.NotFoundError().AppendDetails(
				fmt.Sprintf("权限“%s”不属于该应用", values[i]),
			)
		}
		result = append(result, d)
	}
	return result, nil
}

// ResolvePermissionValue 把单个完整权限串（如 "app:network.read"）解析为权限定义。
// 先按命名空间找到应用，再按权限值查询定义。
func ResolvePermissionValue(ctx context.Context, value string) (*model.PermissionDef, *errs.Error) {
	parsed, e := perm.ParsePermission(value)
	if e != nil {
		return nil, errs.BadRequestError().AppendDetails(
			fmt.Sprintf("权限“%s”格式错误", value),
		)
	}

	application, err := appsvc.GetAppByNamespace(ctx, parsed.Namespace)
	if err != nil {
		return nil, err
	}
	if application == nil {
		return nil, errs.NotFoundError().AppendDetails(
			fmt.Sprintf("应用“%s”不存在", parsed.Namespace),
		)
	}

	path := strings.Join(parsed.Nodes, ".")
	def, err := getPermissionDefByValue(ctx, application.ID, path)
	if err != nil {
		return nil, err
	}
	if def == nil {
		return nil, errs.NotFoundError().AppendDetails(
			fmt.Sprintf("权限“%s”不存在", value),
		)
	}
	return def, nil
}

// getPermissionDefByValueSQL 按应用与权限值查询权限定义。
const getPermissionDefByValueSQL = `
SELECT ` + permissionDefColumns + `
FROM permission_defs
WHERE app_id = $1 AND value = $2
`

// getPermissionDefByValue 按应用与权限值查询权限定义；不存在时返回 (nil, nil)。
func getPermissionDefByValue(ctx context.Context, appID int64, value string) (*model.PermissionDef, *errs.Error) {
	var d model.PermissionDef
	err := db.R.QueryRow(ctx, getPermissionDefByValueSQL, appID, value).Scan(
		&d.ID, &d.AppID, &d.Value, &d.Description, &d.Requestable,
		&d.CreatedBy, &d.CreatedAt, &d.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, errs.CreatePGError(err, "权限定义", "Failed to get permission def by value")
	}
	return &d, nil
}

// ---------------------------------------------------------------------------
// 权限继承（写入，带循环依赖检测）
// ---------------------------------------------------------------------------

// lockPermissionImpliesSQL 按应用加事务级 advisory lock，串行化同一应用的继承写入。
const lockPermissionImpliesSQL = `
SELECT pg_advisory_xact_lock(hashtextextended('permission_implies:' || $1::bigint::text, 0))
`

// selectPermissionDefsByIDsSQL 批量查询权限定义的 id 与应用归属。
const selectPermissionDefsByIDsSQL = `
SELECT id, app_id FROM permission_defs WHERE id = ANY($1::bigint[])
`

// listAppImpliesEdgesSQL 读取某应用内全部继承边，用于替换前重建内存图。
const listAppImpliesEdgesSQL = `
SELECT pi.permission_id, pi.implied_permission_id
FROM permission_implies pi
JOIN permission_defs pd ON pd.id = pi.permission_id
WHERE pd.app_id = $1
`

// deletePermissionImpliesSQL 删除某权限的全部直接出边（Set 语义为整体替换）。
const deletePermissionImpliesSQL = `DELETE FROM permission_implies WHERE permission_id = $1`

// insertPermissionImpliesSQL 批量插入继承边，冲突时忽略。
const insertPermissionImpliesSQL = `
INSERT INTO permission_implies (permission_id, implied_permission_id)
SELECT $1, unnest($2::bigint[])
ON CONFLICT (permission_id, implied_permission_id) DO NOTHING
`

// SetPermissionImplies 用 impliedIDs 整体替换某权限的直接继承关系。
// 写入前校验所有权限定义属于同一应用，并在应用级 advisory lock 内检测循环继承。
// 成功后触发权限目录异步重载。
func SetPermissionImplies(ctx context.Context, appID, permissionID int64, impliedIDs []int64) *errs.Error {
	// 去重并前置拒绝自继承，避免无意义的事务。
	seen := make(map[int64]struct{}, len(impliedIDs))
	unique := make([]int64, 0, len(impliedIDs))
	for _, impliedID := range impliedIDs {
		if impliedID == permissionID {
			return errs.BadRequestError().AppendDetails("权限不能继承自身")
		}
		if _, ok := seen[impliedID]; ok {
			continue
		}
		seen[impliedID] = struct{}{}
		unique = append(unique, impliedID)
	}

	tx, err := db.R.Begin(ctx)
	if err != nil {
		return errs.CreatePGError(err, "权限继承", "Failed to begin transaction")
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	if _, err := tx.Exec(ctx, lockPermissionImpliesSQL, appID); err != nil {
		return errs.CreatePGError(err, "权限继承", "Failed to acquire permission implies lock")
	}

	// 校验涉及的权限定义均存在且属于该应用。
	candidates := make([]int64, 0, len(unique)+1)
	candidates = append(candidates, permissionID)
	candidates = append(candidates, unique...)

	appByDefID := make(map[int64]int64, len(candidates))
	rows, err := tx.Query(ctx, selectPermissionDefsByIDsSQL, candidates)
	if err != nil {
		return errs.CreatePGError(err, "权限继承", "Failed to query permission defs")
	}
	for rows.Next() {
		var id, defAppID int64
		if err := rows.Scan(&id, &defAppID); err != nil {
			rows.Close()
			return errs.CreatePGError(err, "权限继承", "Failed to scan permission def")
		}
		appByDefID[id] = defAppID
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return errs.CreatePGError(err, "权限继承", "Failed to iterate permission defs")
	}
	rows.Close()

	if defAppID, ok := appByDefID[permissionID]; !ok {
		return errs.NotFoundError().AppendDetails("权限定义不存在")
	} else if defAppID != appID {
		return errs.NotFoundError().AppendDetails("权限定义不属于该应用")
	}
	for _, impliedID := range unique {
		defAppID, ok := appByDefID[impliedID]
		if !ok {
			return errs.NotFoundError().AppendDetails(
				fmt.Sprintf("权限定义（ID %d）不存在", impliedID),
			)
		}
		if defAppID != appID {
			return errs.BadRequestError().AppendDetails(
				fmt.Sprintf("权限定义（ID %d）不属于该应用", impliedID), "权限继承不能跨应用",
			)
		}
	}

	// 读取该应用全部继承边，并移除 permissionID 现有的出边（语义为“替换”）。
	edges := make(map[int64][]int64)
	edgeRows, err := tx.Query(ctx, listAppImpliesEdgesSQL, appID)
	if err != nil {
		return errs.CreatePGError(err, "权限继承", "Failed to query permission implies")
	}
	for edgeRows.Next() {
		var from, to int64
		if err := edgeRows.Scan(&from, &to); err != nil {
			edgeRows.Close()
			return errs.CreatePGError(err, "权限继承", "Failed to scan permission implies")
		}
		edges[from] = append(edges[from], to)
	}
	if err := edgeRows.Err(); err != nil {
		edgeRows.Close()
		return errs.CreatePGError(err, "权限继承", "Failed to iterate permission implies")
	}
	edgeRows.Close()
	delete(edges, permissionID)

	// 逐条模拟加边并检测循环依赖。permissionID 的旧出边已移除，
	// 后续新边必须参与检测，否则多条新边组合可能成环。
	for _, impliedID := range unique {
		if perm.WouldCreateCycle(edges, permissionID, impliedID) {
			return errs.BadRequestError().AppendDetails(
				"权限存在循环继承",
				fmt.Sprintf("权限（ID %d）继承权限（ID %d）会形成环", permissionID, impliedID),
			)
		}
		edges[permissionID] = append(edges[permissionID], impliedID)
	}

	// 写入新继承关系并提交。
	if _, err := tx.Exec(ctx, deletePermissionImpliesSQL, permissionID); err != nil {
		return errs.CreatePGError(err, "权限继承", "Failed to delete permission implies")
	}
	if len(unique) > 0 {
		if _, err := tx.Exec(ctx, insertPermissionImpliesSQL, permissionID, unique); err != nil {
			return errs.CreatePGError(err, "权限继承", "Failed to insert permission implies")
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return errs.CreatePGError(err, "权限继承", "Failed to commit transaction")
	}
	perm.NotifyReload()
	return nil
}

// ---------------------------------------------------------------------------
// 权限继承（读取与传递展开）
// ---------------------------------------------------------------------------

// listDirectImpliesInAppSQL 列出某权限在同一应用内直接继承的权限定义。
const listDirectImpliesInAppSQL = `
SELECT ` + permissionDefColumns + `
FROM permission_implies pi
JOIN permission_defs pd ON pd.id = pi.implied_permission_id
WHERE pi.permission_id = $1 AND pd.app_id = $2
ORDER BY pd.id
`

// listTransitiveImpliesInAppSQL 递归展开某权限在同一应用内的传递继承（不含自身）。
const listTransitiveImpliesInAppSQL = `
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
WHERE pd.app_id = $2 AND pd.id <> $1
ORDER BY pd.id
`

// listImpliedByInAppSQL 列出同一应用内直接继承某权限的权限定义。
const listImpliedByInAppSQL = `
SELECT ` + permissionDefColumns + `
FROM permission_implies pi
JOIN permission_defs pd ON pd.id = pi.permission_id
WHERE pi.implied_permission_id = $1 AND pd.app_id = $2
ORDER BY pd.id
`

// ListImplies 查询某权限的直接继承、传递继承列表；两者都限制在当前应用内。
func ListImplies(ctx context.Context, appID, permissionID int64) ([]*model.PermissionDef, []*model.PermissionDef, *errs.Error) {
	if _, err := requirePermissionDefInApp(ctx, appID, permissionID); err != nil {
		return nil, nil, err
	}

	directRows, e := db.R.Query(ctx, listDirectImpliesInAppSQL, permissionID, appID)
	if e != nil {
		return nil, nil, errs.CreatePGError(e, "权限继承", "Failed to query direct permission implies")
	}
	direct, err := collectPermissionDefs(directRows, "权限继承")
	if err != nil {
		return nil, nil, err
	}

	transitiveRows, e := db.R.Query(ctx, listTransitiveImpliesInAppSQL, permissionID, appID)
	if e != nil {
		return nil, nil, errs.CreatePGError(e, "权限继承", "Failed to query transitive permission implies")
	}
	transitive, err := collectPermissionDefs(transitiveRows, "权限继承")
	if err != nil {
		return nil, nil, err
	}
	return direct, transitive, nil
}

// ListImpliedBy 列出同一应用内直接继承某权限的权限定义。
func ListImpliedBy(ctx context.Context, appID, permissionID int64) ([]*model.PermissionDef, *errs.Error) {
	if _, err := requirePermissionDefInApp(ctx, appID, permissionID); err != nil {
		return nil, err
	}

	rows, e := db.R.Query(ctx, listImpliedByInAppSQL, permissionID, appID)
	if e != nil {
		return nil, errs.CreatePGError(e, "权限继承", "Failed to query implied-by permissions")
	}
	return collectPermissionDefs(rows, "权限继承")
}

// requirePermissionDefInApp 校验权限定义存在且属于指定应用，返回该定义。
func requirePermissionDefInApp(ctx context.Context, appID, permissionID int64) (*model.PermissionDef, *errs.Error) {
	def, err := GetPermissionDefInApp(ctx, appID, permissionID)
	if err != nil {
		return nil, err
	}
	if def == nil {
		return nil, errs.NotFoundError().AppendDetails("权限定义不存在")
	}
	return def, nil
}

// ---------------------------------------------------------------------------
// 用户组权限
// ---------------------------------------------------------------------------

// selectRolesInAppSQL 校验用户组存在且属于指定应用。
const selectRolesInAppSQL = `SELECT id FROM roles WHERE id = $1 AND app_id = $2`

// deleteRolePermissionsInAppSQL 删除用户组在当前应用内的全部组权限。
const deleteRolePermissionsInAppSQL = `
DELETE FROM role_permissions
WHERE role_id = $1
  AND permission_id IN (SELECT id FROM permission_defs WHERE app_id = $2)
`

// insertRolePermissionsSQL 批量插入组权限，冲突时忽略。
const insertRolePermissionsSQL = `
INSERT INTO role_permissions (role_id, permission_id)
SELECT $1, unnest($2::bigint[])
ON CONFLICT (role_id, permission_id) DO NOTHING
`

// AddRolePermissions 向用户组追加一批权限（只增不减，重复添加幂等）。
// 注意：调用方需自行保证权限定义属于目标应用，本函数不做应用归属校验。
func AddRolePermissions(ctx context.Context, roleID int64, permissionIDs []int64) *errs.Error {
	if len(permissionIDs) == 0 {
		return nil
	}
	// 去重，避免重复插入。
	seen := make(map[int64]struct{}, len(permissionIDs))
	unique := make([]int64, 0, len(permissionIDs))
	for _, permissionID := range permissionIDs {
		if _, ok := seen[permissionID]; ok {
			continue
		}
		seen[permissionID] = struct{}{}
		unique = append(unique, permissionID)
	}

	if _, err := db.R.Exec(ctx, insertRolePermissionsSQL, roleID, unique); err != nil {
		return errs.CreatePGError(err, "用户组权限", "Failed to add role permissions")
	}
	return nil
}

// SetRolePermissions 用 permissionIDs 整体替换用户组在当前应用内的组权限。
// 事务内校验用户组与权限定义的应用归属；成功后不触发权限目录重载（角色变化不改变目录）。
func SetRolePermissions(ctx context.Context, appID, roleID int64, permissionIDs []int64) *errs.Error {
	// 去重，避免重复插入。
	seen := make(map[int64]struct{}, len(permissionIDs))
	unique := make([]int64, 0, len(permissionIDs))
	for _, permissionID := range permissionIDs {
		if _, ok := seen[permissionID]; ok {
			continue
		}
		seen[permissionID] = struct{}{}
		unique = append(unique, permissionID)
	}

	tx, err := db.R.Begin(ctx)
	if err != nil {
		return errs.CreatePGError(err, "用户组权限", "Failed to begin transaction")
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	// 校验用户组属于该应用。
	var foundRoleID int64
	err = tx.QueryRow(ctx, selectRolesInAppSQL, roleID, appID).Scan(&foundRoleID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errs.NotFoundError().AppendDetails("用户组不存在")
		}
		return errs.CreatePGError(err, "用户组权限", "Failed to get role in app")
	}

	// 校验权限定义均存在且属于该应用。
	if len(unique) > 0 {
		appByDefID := make(map[int64]int64, len(unique))
		rows, err := tx.Query(ctx, selectPermissionDefsByIDsSQL, unique)
		if err != nil {
			return errs.CreatePGError(err, "用户组权限", "Failed to query permission defs")
		}
		for rows.Next() {
			var id, defAppID int64
			if err := rows.Scan(&id, &defAppID); err != nil {
				rows.Close()
				return errs.CreatePGError(err, "用户组权限", "Failed to scan permission def")
			}
			appByDefID[id] = defAppID
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return errs.CreatePGError(err, "用户组权限", "Failed to iterate permission defs")
		}
		rows.Close()

		for _, permissionID := range unique {
			defAppID, ok := appByDefID[permissionID]
			if !ok {
				return errs.NotFoundError().AppendDetails(
					fmt.Sprintf("权限定义（ID %d）不存在", permissionID),
				)
			}
			if defAppID != appID {
				return errs.BadRequestError().AppendDetails(
					fmt.Sprintf("权限定义（ID %d）不属于该应用", permissionID),
				)
			}
		}
	}

	// 替换用户组的组权限并提交。
	if _, err := tx.Exec(ctx, deleteRolePermissionsInAppSQL, roleID, appID); err != nil {
		return errs.CreatePGError(err, "用户组权限", "Failed to delete role permissions")
	}
	if len(unique) > 0 {
		if _, err := tx.Exec(ctx, insertRolePermissionsSQL, roleID, unique); err != nil {
			return errs.CreatePGError(err, "用户组权限", "Failed to insert role permissions")
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return errs.CreatePGError(err, "用户组权限", "Failed to commit transaction")
	}
	return nil
}

// ---------------------------------------------------------------------------
// 用户组成员
// ---------------------------------------------------------------------------

// RoleUser 是用户组成员列表项：成员关系（授予人、有效期）加上用户基本资料。
type RoleUser struct {
	UserID     int64       `json:"user_id"`     // 用户 ID
	Username   string      `json:"username"`    // 用户名
	Nickname   null.String `json:"nickname"`    // 昵称，NULL 表示未设置
	Deleted    bool        `json:"deleted"`     // 用户是否已注销（软删除）
	GrantedBy  null.Int64  `json:"granted_by"`  // 授予人用户 ID，NULL 表示系统
	ValidFrom  null.Time   `json:"valid_from"`  // 成员关系生效时间，NULL 表示立即生效
	ValidUntil null.Time   `json:"valid_until"` // 成员关系过期时间，NULL 表示永久有效
	CreatedAt  time.Time   `json:"created_at"`  // 成员关系创建时间
}

// countRoleUsersSQLForManage 统计某用户组的成员数量。
const countRoleUsersSQLForManage = `SELECT count(*) FROM user_roles WHERE role_id = $1`

// listRoleUsersSQL 分页列出某用户组的成员（附带用户资料），按加入时间倒序。
const listRoleUsersSQL = `
SELECT ur.user_id, u.username, u.nickname, (u.deleted_at IS NOT NULL) AS deleted,
       ur.granted_by, ur.valid_from, ur.valid_until, ur.created_at
FROM user_roles ur
JOIN users u ON u.id = ur.user_id
WHERE ur.role_id = $1
ORDER BY ur.created_at DESC, ur.user_id DESC
LIMIT $2 OFFSET $3
`

// ListRoleUsers 分页查询某用户组的成员（含已注销用户），返回当前页与总数。
func ListRoleUsers(ctx context.Context, roleID int64, limit, offset int32) ([]*RoleUser, int32, *errs.Error) {
	limit, offset = search.NormalizePagination(limit, offset)

	var count int32
	if err := db.R.QueryRow(ctx, countRoleUsersSQLForManage, roleID).Scan(&count); err != nil {
		return nil, 0, errs.CreatePGError(err, "用户组成员", "Failed to count role users")
	}

	rows, err := db.R.Query(ctx, listRoleUsersSQL, roleID, limit, offset)
	if err != nil {
		return nil, 0, errs.CreatePGError(err, "用户组成员", "Failed to query role users")
	}
	defer rows.Close()

	users := make([]*RoleUser, 0)
	for rows.Next() {
		var u RoleUser
		if err := rows.Scan(
			&u.UserID, &u.Username, &u.Nickname, &u.Deleted,
			&u.GrantedBy, &u.ValidFrom, &u.ValidUntil, &u.CreatedAt,
		); err != nil {
			return nil, 0, errs.CreatePGError(err, "用户组成员", "Failed to scan role user")
		}
		users = append(users, &u)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, errs.CreatePGError(err, "用户组成员", "Failed to iterate role users")
	}
	return users, count, nil
}

// ---------------------------------------------------------------------------
// 应用范围：应用直接授予用户的权限
// ---------------------------------------------------------------------------

// countUserPermissionGrantsInAppSQL 统计某应用直接授予某用户的权限数量。
const countUserPermissionGrantsInAppSQL = `
SELECT count(*) FROM user_permission_grants
WHERE user_id = $1 AND granted_by_app_id = $2
`

// listUserPermissionGrantsInAppSQL 分页列出某应用直接授予某用户的权限，按 id 倒序。
const listUserPermissionGrantsInAppSQL = `
SELECT id, user_id, permission, granted_by_user_id, granted_by_app_id,
       valid_from, valid_until, note, created_at, updated_at
FROM user_permission_grants
WHERE user_id = $1 AND granted_by_app_id = $2
ORDER BY id DESC
LIMIT $3 OFFSET $4
`

// ListUserPermissionGrantsInApp 分页查询某应用直接授予某用户的权限列表。
func ListUserPermissionGrantsInApp(
	ctx context.Context,
	userID, appID int64,
	limit, offset int32,
) ([]*model.UserPermissionGrant, int32, *errs.Error) {
	limit, offset = search.NormalizePagination(limit, offset)

	var count int32
	if e := db.R.QueryRow(ctx, countUserPermissionGrantsInAppSQL, userID, appID).Scan(&count); e != nil {
		return nil, 0, errs.CreatePGError(e, "用户授权", "Failed to count app user permission grants")
	}

	rows, e := db.R.Query(ctx, listUserPermissionGrantsInAppSQL, userID, appID, limit, offset)
	if e != nil {
		return nil, 0, errs.CreatePGError(e, "用户授权", "Failed to query app user permission grants")
	}
	grants, err := collectUserPermissionGrants(rows, "应用用户授权列表")
	if err != nil {
		return nil, 0, err
	}
	return grants, count, nil
}
