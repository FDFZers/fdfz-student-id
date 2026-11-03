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

const permissionDefColumns = `
id, app_id, value, description, requestable, created_by, created_at, updated_at
`

const appPermissionDefSQL = `
SELECT ` + permissionDefColumns + `
FROM permission_defs
WHERE id = $1 AND app_id = $2
`

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
		return nil, errs.CreatePGError(err, "权限定义", "Failed to get permission def in app").
			AppendDetails("获取权限定义失败")
	}
	return &d, nil
}

const appRoleSQL = `
SELECT id, app_id, name, note, is_public, created_at, updated_at
FROM roles
WHERE id = $1 AND app_id = $2
`

func GetRoleInApp(ctx context.Context, appID, roleID int64) (*model.Role, *errs.Error) {
	var r model.Role
	err := db.R.QueryRow(ctx, appRoleSQL, roleID, appID).Scan(
		&r.ID, &r.AppID, &r.Name, &r.Note, &r.Public, &r.CreatedAt, &r.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, errs.CreatePGError(err, "用户组", "Failed to get role in app").
			AppendDetails("获取用户组失败")
	}
	return &r, nil
}

// ---------------------------------------------------------------------------
// 全局列表
// ---------------------------------------------------------------------------

const countAllPermissionDefsSQL = `
SELECT count(*) FROM permission_defs WHERE ($1::bigint IS NULL OR app_id = $1)
`

const listAllPermissionDefsSQL = `
SELECT ` + permissionDefColumns + `
FROM permission_defs
WHERE ($1::bigint IS NULL OR app_id = $1)
ORDER BY id
LIMIT $2 OFFSET $3
`

func ListAllPermissionDefs(ctx context.Context, appID *int64, limit, offset int32) ([]*model.PermissionDef, int32, *errs.Error) {
	limit, offset = search.NormalizePagination(limit, offset)

	var count int32
	if err := db.R.QueryRow(ctx, countAllPermissionDefsSQL, appID).Scan(&count); err != nil {
		return nil, 0, errs.CreatePGError(err, "权限定义", "Failed to count permission defs").
			AppendDetails("权限定义列表获取失败")
	}

	rows, err := db.R.Query(ctx, listAllPermissionDefsSQL, appID, limit, offset)
	if err != nil {
		return nil, 0, errs.CreatePGError(err, "权限定义", "Failed to query permission defs").
			AppendDetails("权限定义列表获取失败")
	}

	defs, e := collectPermissionDefs(rows, "权限定义列表")
	if e != nil {
		return nil, 0, e
	}
	return defs, count, nil
}

const countAllRolesSQL = `SELECT count(*) FROM roles WHERE ($1::bigint IS NULL OR app_id = $1)`

const listAllRolesSQL = `
SELECT id, app_id, name, note, is_public, created_at, updated_at
FROM roles
WHERE ($1::bigint IS NULL OR app_id = $1)
ORDER BY id
LIMIT $2 OFFSET $3
`

func ListAllRoles(ctx context.Context, appID *int64, limit, offset int32) ([]*model.Role, int32, *errs.Error) {
	limit, offset = search.NormalizePagination(limit, offset)

	var count int32
	if err := db.R.QueryRow(ctx, countAllRolesSQL, appID).Scan(&count); err != nil {
		return nil, 0, errs.CreatePGError(err, "用户组", "Failed to count roles").
			AppendDetails("用户组列表获取失败")
	}

	rows, err := db.R.Query(ctx, listAllRolesSQL, appID, limit, offset)
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

// ---------------------------------------------------------------------------
// 完整权限串解析
// ---------------------------------------------------------------------------

const resolvePermissionValuesSQL = `
SELECT ` + permissionDefColumns + `
FROM permission_defs
WHERE app_id = $1 AND value = ANY($2::text[])
`

func parseFullPermission(value, namespace string) (string, *errs.Error) {
	parsed, err := perm.ParsePermission(value)
	if err != nil {
		return "", errs.BadRequestError().AppendDetails(
			fmt.Sprintf("权限“%s”格式非法", value), "解析权限失败",
		)
	}
	if namespace != "" && parsed.Namespace != namespace {
		return "", errs.BadRequestError().AppendDetails(
			fmt.Sprintf("权限“%s”的命名空间不是“%s”", value, namespace), "解析权限失败",
		)
	}
	return strings.Join(parsed.Nodes, "."), nil
}

func ResolvePermissionValues(ctx context.Context, appID int64, namespace string, values []string) ([]*model.PermissionDef, *errs.Error) {
	paths := make([]string, 0, len(values))
	for _, value := range values {
		path, e := parseFullPermission(value, namespace)
		if e != nil {
			return nil, e
		}
		paths = append(paths, path)
	}

	if len(paths) == 0 {
		return make([]*model.PermissionDef, 0), nil
	}

	rows, err := db.R.Query(ctx, resolvePermissionValuesSQL, appID, paths)
	if err != nil {
		return nil, errs.CreatePGError(err, "权限定义", "Failed to query permission defs by values").
			AppendDetails("解析权限失败")
	}
	defs, e := collectPermissionDefs(rows, "权限定义")
	if e != nil {
		return nil, e
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
				fmt.Sprintf("权限“%s”不存在", values[i]), "解析权限失败",
			)
		}
		if d.AppID != appID {
			// 查询条件已限定 app_id，这里仅作防御性校验。
			return nil, errs.NotFoundError().AppendDetails(
				fmt.Sprintf("权限“%s”不属于该应用", values[i]), "解析权限失败",
			)
		}
		result = append(result, d)
	}
	return result, nil
}

func ResolvePermissionValue(ctx context.Context, value string) (*model.PermissionDef, *errs.Error) {
	parsed, err := perm.ParsePermission(value)
	if err != nil {
		return nil, errs.BadRequestError().AppendDetails(
			fmt.Sprintf("权限“%s”格式非法", value), "解析权限失败",
		)
	}

	application, e := appsvc.GetAppByNamespace(ctx, parsed.Namespace)
	if e != nil {
		return nil, e.AppendDetails("解析权限失败")
	}
	if application == nil {
		return nil, errs.NotFoundError().AppendDetails(
			fmt.Sprintf("应用“%s”不存在", parsed.Namespace), "解析权限失败",
		)
	}

	path := strings.Join(parsed.Nodes, ".")
	def, e := getPermissionDefByValue(ctx, application.ID, path)
	if e != nil {
		return nil, e.AppendDetails("解析权限失败")
	}
	if def == nil {
		return nil, errs.NotFoundError().AppendDetails(
			fmt.Sprintf("权限“%s”不存在", value), "解析权限失败",
		)
	}
	return def, nil
}

const getPermissionDefByValueSQL = `
SELECT ` + permissionDefColumns + `
FROM permission_defs
WHERE app_id = $1 AND value = $2
`

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
		return nil, errs.CreatePGError(err, "权限定义", "Failed to get permission def by value").
			AppendDetails("获取权限定义失败")
	}
	return &d, nil
}

// ---------------------------------------------------------------------------
// 权限继承（写入，带循环依赖检测）
// ---------------------------------------------------------------------------

const lockPermissionImpliesSQL = `
SELECT pg_advisory_xact_lock(hashtextextended('permission_implies:' || $1::bigint::text, 0))
`

const selectPermissionDefsByIDsSQL = `
SELECT id, app_id FROM permission_defs WHERE id = ANY($1::bigint[])
`

const listAppImpliesEdgesSQL = `
SELECT pi.permission_id, pi.implied_permission_id
FROM permission_implies pi
JOIN permission_defs pd ON pd.id = pi.permission_id
WHERE pd.app_id = $1
`

const deletePermissionImpliesSQL = `DELETE FROM permission_implies WHERE permission_id = $1`

const insertPermissionImpliesSQL = `
INSERT INTO permission_implies (permission_id, implied_permission_id)
SELECT $1, unnest($2::bigint[])
ON CONFLICT (permission_id, implied_permission_id) DO NOTHING
`

func SetPermissionImplies(ctx context.Context, appID, permissionID int64, impliedIDs []int64) *errs.Error {
	// 去重并前置拒绝自继承，避免无意义的事务。
	seen := make(map[int64]struct{}, len(impliedIDs))
	unique := make([]int64, 0, len(impliedIDs))
	for _, impliedID := range impliedIDs {
		if impliedID == permissionID {
			return errs.BadRequestError().AppendDetails("权限不能继承自身", "设置权限继承失败")
		}
		if _, ok := seen[impliedID]; ok {
			continue
		}
		seen[impliedID] = struct{}{}
		unique = append(unique, impliedID)
	}

	tx, err := db.R.Begin(ctx)
	if err != nil {
		return errs.CreatePGError(err, "权限继承", "Failed to begin transaction").
			AppendDetails("设置权限继承失败")
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	if _, err := tx.Exec(ctx, lockPermissionImpliesSQL, appID); err != nil {
		return errs.CreatePGError(err, "权限继承", "Failed to acquire permission implies lock").
			AppendDetails("设置权限继承失败")
	}

	// 校验涉及的权限定义均存在且属于该应用。
	candidates := make([]int64, 0, len(unique)+1)
	candidates = append(candidates, permissionID)
	candidates = append(candidates, unique...)

	appByDefID := make(map[int64]int64, len(candidates))
	rows, err := tx.Query(ctx, selectPermissionDefsByIDsSQL, candidates)
	if err != nil {
		return errs.CreatePGError(err, "权限继承", "Failed to query permission defs").
			AppendDetails("设置权限继承失败")
	}
	for rows.Next() {
		var id, defAppID int64
		if scanErr := rows.Scan(&id, &defAppID); scanErr != nil {
			rows.Close()
			return errs.CreatePGError(scanErr, "权限继承", "Failed to scan permission def").
				AppendDetails("设置权限继承失败")
		}
		appByDefID[id] = defAppID
	}
	if rowsErr := rows.Err(); rowsErr != nil {
		rows.Close()
		return errs.CreatePGError(rowsErr, "权限继承", "Failed to iterate permission defs").
			AppendDetails("设置权限继承失败")
	}
	rows.Close()

	if defAppID, ok := appByDefID[permissionID]; !ok {
		return errs.NotFoundError().AppendDetails("权限定义不存在", "设置权限继承失败")
	} else if defAppID != appID {
		return errs.NotFoundError().AppendDetails("权限定义不属于该应用", "设置权限继承失败")
	}
	for _, impliedID := range unique {
		defAppID, ok := appByDefID[impliedID]
		if !ok {
			return errs.NotFoundError().AppendDetails(
				fmt.Sprintf("需要继承的权限（ID %d）不存在", impliedID), "设置权限继承失败",
			)
		}
		if defAppID != appID {
			return errs.BadRequestError().AppendDetails(
				fmt.Sprintf("需要继承的权限（ID %d）不属于该应用", impliedID), "权限继承不能跨应用", "设置权限继承失败",
			)
		}
	}

	// 读取该应用全部继承边，并移除 permissionID 现有的出边（语义为“替换”）。
	edges := make(map[int64][]int64)
	edgeRows, err := tx.Query(ctx, listAppImpliesEdgesSQL, appID)
	if err != nil {
		return errs.CreatePGError(err, "权限继承", "Failed to query permission implies").
			AppendDetails("设置权限继承失败")
	}
	for edgeRows.Next() {
		var from, to int64
		if scanErr := edgeRows.Scan(&from, &to); scanErr != nil {
			edgeRows.Close()
			return errs.CreatePGError(scanErr, "权限继承", "Failed to scan permission implies").
				AppendDetails("设置权限继承失败")
		}
		edges[from] = append(edges[from], to)
	}
	if rowsErr := edgeRows.Err(); rowsErr != nil {
		edgeRows.Close()
		return errs.CreatePGError(rowsErr, "权限继承", "Failed to iterate permission implies").
			AppendDetails("设置权限继承失败")
	}
	edgeRows.Close()
	delete(edges, permissionID)

	// 逐条模拟加边并检测循环依赖。permissionID 的旧出边已移除，
	// 后续新边必须参与检测，否则多条新边组合可能成环。
	for _, impliedID := range unique {
		if perm.WouldCreateCycle(edges, permissionID, impliedID) {
			return errs.BadRequestError().AppendDetails(
				"权限继承存在循环依赖", "设置权限继承失败",
				fmt.Sprintf("权限（ID %d）继承权限（ID %d）会形成环", permissionID, impliedID),
			)
		}
		edges[permissionID] = append(edges[permissionID], impliedID)
	}

	// 写入新继承关系。
	if _, err := tx.Exec(ctx, deletePermissionImpliesSQL, permissionID); err != nil {
		return errs.CreatePGError(err, "权限继承", "Failed to delete permission implies").
			AppendDetails("设置权限继承失败")
	}
	if len(unique) > 0 {
		if _, err := tx.Exec(ctx, insertPermissionImpliesSQL, permissionID, unique); err != nil {
			return errs.CreatePGError(err, "权限继承", "Failed to insert permission implies").
				AppendDetails("设置权限继承失败")
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return errs.CreatePGError(err, "权限继承", "Failed to commit transaction").
			AppendDetails("设置权限继承失败")
	}
	perm.NotifyReload()
	return nil
}

// ---------------------------------------------------------------------------
// 权限继承
// ---------------------------------------------------------------------------

const listDirectImpliesInAppSQL = `
SELECT ` + permissionDefColumns + `
FROM permission_implies pi
JOIN permission_defs pd ON pd.id = pi.implied_permission_id
WHERE pi.permission_id = $1 AND pd.app_id = $2
ORDER BY pd.id
`

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

const listImpliedByInAppSQL = `
SELECT ` + permissionDefColumns + `
FROM permission_implies pi
JOIN permission_defs pd ON pd.id = pi.permission_id
WHERE pi.implied_permission_id = $1 AND pd.app_id = $2
ORDER BY pd.id
`

func ListImplies(ctx context.Context, appID, permissionID int64) ([]*model.PermissionDef, []*model.PermissionDef, *errs.Error) {
	if _, e := requirePermissionDefInApp(ctx, appID, permissionID); e != nil {
		return nil, nil, e
	}

	directRows, err := db.R.Query(ctx, listDirectImpliesInAppSQL, permissionID, appID)
	if err != nil {
		return nil, nil, errs.CreatePGError(err, "权限继承", "Failed to query direct permission implies").
			AppendDetails("获取权限继承失败")
	}
	direct, e := collectPermissionDefs(directRows, "权限继承")
	if e != nil {
		return nil, nil, e
	}

	transitiveRows, err := db.R.Query(ctx, listTransitiveImpliesInAppSQL, permissionID, appID)
	if err != nil {
		return nil, nil, errs.CreatePGError(err, "权限继承", "Failed to query transitive permission implies").
			AppendDetails("获取权限继承失败")
	}
	transitive, e := collectPermissionDefs(transitiveRows, "权限继承")
	if e != nil {
		return nil, nil, e
	}
	return direct, transitive, nil
}

func ListImpliedBy(ctx context.Context, appID, permissionID int64) ([]*model.PermissionDef, *errs.Error) {
	if _, e := requirePermissionDefInApp(ctx, appID, permissionID); e != nil {
		return nil, e
	}

	rows, err := db.R.Query(ctx, listImpliedByInAppSQL, permissionID, appID)
	if err != nil {
		return nil, errs.CreatePGError(err, "权限继承", "Failed to query implied-by permissions").
			AppendDetails("获取权限继承失败")
	}
	return collectPermissionDefs(rows, "权限继承")
}

func requirePermissionDefInApp(ctx context.Context, appID, permissionID int64) (*model.PermissionDef, *errs.Error) {
	def, err := GetPermissionDefInApp(ctx, appID, permissionID)
	if err != nil {
		return nil, err
	}
	if def == nil {
		return nil, errs.NotFoundError().AppendDetails("权限定义不存在", "获取权限继承失败")
	}
	return def, nil
}

// ---------------------------------------------------------------------------
// 用户组权限
// ---------------------------------------------------------------------------

const selectRolesInAppSQL = `SELECT id FROM roles WHERE id = $1 AND app_id = $2`

const deleteRolePermissionsInAppSQL = `
DELETE FROM role_permissions
WHERE role_id = $1
  AND permission_id IN (SELECT id FROM permission_defs WHERE app_id = $2)
`

const insertRolePermissionsSQL = `
INSERT INTO role_permissions (role_id, permission_id)
SELECT $1, unnest($2::bigint[])
ON CONFLICT (role_id, permission_id) DO NOTHING
`

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
		return errs.CreatePGError(err, "用户组权限", "Failed to add role permissions").
			AppendDetails("添加用户组权限失败")
	}
	return nil
}

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
		return errs.CreatePGError(err, "用户组权限", "Failed to begin transaction").
			AppendDetails("设置用户组权限失败")
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	var foundRoleID int64
	err = tx.QueryRow(ctx, selectRolesInAppSQL, roleID, appID).Scan(&foundRoleID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errs.NotFoundError().AppendDetails("用户组不存在", "设置用户组权限失败")
		}
		return errs.CreatePGError(err, "用户组权限", "Failed to get role in app").
			AppendDetails("设置用户组权限失败")
	}

	if len(unique) > 0 {
		appByDefID := make(map[int64]int64, len(unique))
		rows, qErr := tx.Query(ctx, selectPermissionDefsByIDsSQL, unique)
		if qErr != nil {
			return errs.CreatePGError(qErr, "用户组权限", "Failed to query permission defs").
				AppendDetails("设置用户组权限失败")
		}
		for rows.Next() {
			var id, defAppID int64
			if scanErr := rows.Scan(&id, &defAppID); scanErr != nil {
				rows.Close()
				return errs.CreatePGError(scanErr, "用户组权限", "Failed to scan permission def").
					AppendDetails("设置用户组权限失败")
			}
			appByDefID[id] = defAppID
		}
		if rowsErr := rows.Err(); rowsErr != nil {
			rows.Close()
			return errs.CreatePGError(rowsErr, "用户组权限", "Failed to iterate permission defs").
				AppendDetails("设置用户组权限失败")
		}
		rows.Close()

		for _, permissionID := range unique {
			defAppID, ok := appByDefID[permissionID]
			if !ok {
				return errs.NotFoundError().AppendDetails(
					fmt.Sprintf("权限定义（ID %d）不存在", permissionID), "设置用户组权限失败",
				)
			}
			if defAppID != appID {
				return errs.BadRequestError().AppendDetails(
					fmt.Sprintf("权限定义（ID %d）不属于该应用", permissionID), "设置用户组权限失败",
				)
			}
		}
	}

	if _, err := tx.Exec(ctx, deleteRolePermissionsInAppSQL, roleID, appID); err != nil {
		return errs.CreatePGError(err, "用户组权限", "Failed to delete role permissions").
			AppendDetails("设置用户组权限失败")
	}
	if len(unique) > 0 {
		if _, err := tx.Exec(ctx, insertRolePermissionsSQL, roleID, unique); err != nil {
			return errs.CreatePGError(err, "用户组权限", "Failed to insert role permissions").
				AppendDetails("设置用户组权限失败")
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return errs.CreatePGError(err, "用户组权限", "Failed to commit transaction").
			AppendDetails("设置用户组权限失败")
	}
	return nil
}

// ---------------------------------------------------------------------------
// 用户组成员
// ---------------------------------------------------------------------------

type RoleUser struct {
	UserID     int64       `json:"user_id"`
	Username   string      `json:"username"`
	Nickname   null.String `json:"nickname"`
	Deleted    bool        `json:"deleted"`
	GrantedBy  null.Int64  `json:"granted_by"`
	ValidFrom  null.Time   `json:"valid_from"`
	ValidUntil null.Time   `json:"valid_until"`
	CreatedAt  time.Time   `json:"created_at"`
}

const countRoleUsersSQLForManage = `SELECT count(*) FROM user_roles WHERE role_id = $1`

const listRoleUsersSQL = `
SELECT ur.user_id, u.username, u.nickname, (u.deleted_at IS NOT NULL) AS deleted,
       ur.granted_by, ur.valid_from, ur.valid_until, ur.created_at
FROM user_roles ur
JOIN users u ON u.id = ur.user_id
WHERE ur.role_id = $1
ORDER BY ur.created_at DESC, ur.user_id DESC
LIMIT $2 OFFSET $3
`

func ListRoleUsers(ctx context.Context, roleID int64, limit, offset int32) ([]*RoleUser, int32, *errs.Error) {
	limit, offset = search.NormalizePagination(limit, offset)

	var count int32
	if err := db.R.QueryRow(ctx, countRoleUsersSQLForManage, roleID).Scan(&count); err != nil {
		return nil, 0, errs.CreatePGError(err, "用户组成员", "Failed to count role users").
			AppendDetails("用户组成员列表获取失败")
	}

	rows, err := db.R.Query(ctx, listRoleUsersSQL, roleID, limit, offset)
	if err != nil {
		return nil, 0, errs.CreatePGError(err, "用户组成员", "Failed to query role users").
			AppendDetails("用户组成员列表获取失败")
	}
	defer rows.Close()

	users := make([]*RoleUser, 0)
	for rows.Next() {
		var u RoleUser
		if scanErr := rows.Scan(
			&u.UserID, &u.Username, &u.Nickname, &u.Deleted,
			&u.GrantedBy, &u.ValidFrom, &u.ValidUntil, &u.CreatedAt,
		); scanErr != nil {
			return nil, 0, errs.CreatePGError(scanErr, "用户组成员", "Failed to scan role user").
				AppendDetails("用户组成员列表获取失败")
		}
		users = append(users, &u)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, errs.CreatePGError(err, "用户组成员", "Failed to iterate role users").
			AppendDetails("用户组成员列表获取失败")
	}
	return users, count, nil
}

// ---------------------------------------------------------------------------
// 应用范围：应用直接授予用户的权限
// ---------------------------------------------------------------------------

const countUserPermissionGrantsInAppSQL = `
SELECT count(*) FROM user_permission_grants
WHERE user_id = $1 AND granted_by_app_id = $2
`

const listUserPermissionGrantsInAppSQL = `
SELECT id, user_id, permission, granted_by_user_id, granted_by_app_id,
       valid_from, valid_until, note, created_at, updated_at
FROM user_permission_grants
WHERE user_id = $1 AND granted_by_app_id = $2
ORDER BY id DESC
LIMIT $3 OFFSET $4
`

func ListUserPermissionGrantsInApp(
	ctx context.Context,
	userID, appID int64,
	limit, offset int32,
) ([]*model.UserPermissionGrant, int32, *errs.Error) {
	limit, offset = search.NormalizePagination(limit, offset)

	var count int32
	if err := db.R.QueryRow(ctx, countUserPermissionGrantsInAppSQL, userID, appID).Scan(&count); err != nil {
		return nil, 0, errs.CreatePGError(err, "用户授权", "Failed to count app user permission grants").
			AppendDetails("应用用户授权列表获取失败")
	}

	rows, err := db.R.Query(ctx, listUserPermissionGrantsInAppSQL, userID, appID, limit, offset)
	if err != nil {
		return nil, 0, errs.CreatePGError(err, "用户授权", "Failed to query app user permission grants").
			AppendDetails("应用用户授权列表获取失败")
	}
	grants, e := collectUserPermissionGrants(rows, "应用用户授权列表")
	if e != nil {
		return nil, 0, e
	}
	return grants, count, nil
}
