package app

import (
	"context"
	"errors"
	"time"

	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/service/perm"
	"fdfz-student-id/internal/util/crypto"

	"github.com/guregu/null/v6"
	"github.com/jackc/pgx/v5"
)

// CoreNamespace 是内置 student_id 应用的命名空间：该应用承载全站权限定义，
// 停用、删除或修改其命名空间都会导致权限目录失效。
const CoreNamespace = "student_id"

// appColumns 是 oauth_apps 的查询列清单；顺序必须与 scanApp 的 Scan 参数一致。
const appColumns = `
id, namespace, owner_user_id, secret_hash, name, description, homepage_url,
client_type, redirect_uris, requested_perms, status,
created_at, updated_at, deleted_at
`

// scanApp 扫描一行 oauth_apps 数据；记录不存在时返回 (nil, nil)，由调用方决定如何报错。
func scanApp(row pgx.Row, item string) (*model.OAuthApp, *errs.Error) {
	var a model.OAuthApp
	err := row.Scan(
		&a.ID, &a.Namespace, &a.OwnerUserID, &a.SecretHash, &a.Name, &a.Description, &a.HomepageURL,
		&a.ClientType, &a.RedirectURIs, &a.RequestedPerms, &a.Status,
		&a.CreatedAt, &a.UpdatedAt, &a.DeletedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, errs.CreatePGError(err, item, "Failed to scan app").AppendDetails(item + "获取失败")
	}
	return &a, nil
}

// collectApps 扫描应用列表并关闭 rows，供各列表查询复用。
func collectApps(rows pgx.Rows, item string) ([]*model.OAuthApp, *errs.Error) {
	defer rows.Close()

	apps := make([]*model.OAuthApp, 0)
	for rows.Next() {
		a, err := scanApp(rows, item)
		if err != nil {
			return nil, err
		}
		apps = append(apps, a)
	}
	if err := rows.Err(); err != nil {
		return nil, errs.CreatePGError(err, item, "Failed to iterate apps").AppendDetails(item + "列表获取失败")
	}
	return apps, nil
}

const getAppByIDSQL = `SELECT ` + appColumns + ` FROM oauth_apps WHERE id = $1 AND deleted_at IS NULL`

// GetAppByID 按 ID 返回未删除的应用（含已停用应用）；不存在时返回 (nil, nil)。
func GetAppByID(ctx context.Context, id int64) (*model.OAuthApp, *errs.Error) {
	return scanApp(db.R.QueryRow(ctx, getAppByIDSQL, id), "应用")
}

const getAppByNamespaceSQL = `SELECT ` + appColumns + ` FROM oauth_apps WHERE lower(namespace) = lower($1) AND deleted_at IS NULL`

// GetAppByNamespace 按命名空间大小写不敏感地返回未删除的应用；不存在时返回 (nil, nil)。
// 注意：应用可能处于 suspended 状态，调用方如需只接受 active 应用应自行判断 Status。
func GetAppByNamespace(ctx context.Context, namespace string) (*model.OAuthApp, *errs.Error) {
	return scanApp(db.R.QueryRow(ctx, getAppByNamespaceSQL, namespace), "应用")
}

const listOwnedAppIDsSQL = `
SELECT id FROM oauth_apps
WHERE owner_user_id = $1 AND deleted_at IS NULL AND status = 'active'
ORDER BY id
`

// ListOwnedAppIDs 返回用户名下有效应用的 ID 列表（用于写入访问令牌的 owned_apps 声明）。
// 只统计 active 且未删除的应用，停用应用不参与「应用所有者」鉴权。
func ListOwnedAppIDs(ctx context.Context, userID int64) ([]int64, *errs.Error) {
	rows, err := db.R.Query(ctx, listOwnedAppIDsSQL, userID)
	if err != nil {
		return nil, errs.CreatePGError(err, "应用", "Failed to list owned app ids").AppendDetails("应用列表获取失败")
	}
	defer rows.Close()

	ids := make([]int64, 0)
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, errs.CreatePGError(err, "应用", "Failed to scan owned app id").AppendDetails("应用列表获取失败")
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, errs.CreatePGError(err, "应用", "Failed to iterate owned app ids").AppendDetails("应用列表获取失败")
	}
	return ids, nil
}

const listAllAppsSQL = `SELECT ` + appColumns + ` FROM oauth_apps WHERE deleted_at IS NULL ORDER BY id`

// ListAllApps 返回全部未删除的应用（含停用应用，仅建议在管理员语境下使用）。
func ListAllApps(ctx context.Context) ([]*model.OAuthApp, *errs.Error) {
	rows, err := db.R.Query(ctx, listAllAppsSQL)
	if err != nil {
		return nil, errs.CreatePGError(err, "应用", "Failed to list apps").AppendDetails("应用列表获取失败")
	}
	return collectApps(rows, "应用")
}

// createAppSQL 新建应用并回填全部字段。
const createAppSQL = `
INSERT INTO oauth_apps (
    namespace, owner_user_id, secret_hash, name, description, homepage_url,
    client_type, redirect_uris, requested_perms, status
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
RETURNING ` + appColumns

// CreateApp 新建应用；命名空间唯一性由数据库部分唯一索引保证（冲突时返回 conflict）。
func CreateApp(ctx context.Context, a *model.OAuthApp) *errs.Error {
	if a == nil {
		return errs.BadRequestError().AppendDetails("未提供参数")
	}
	if a.RedirectURIs == nil {
		a.RedirectURIs = []string{}
	}
	if a.RequestedPerms == nil {
		a.RequestedPerms = []string{}
	}
	if !a.ClientType.IsConfidential() {
		a.SecretHash = null.String{}
	}
	created, err := scanApp(db.R.QueryRow(ctx, createAppSQL,
		a.Namespace, a.OwnerUserID, a.SecretHash, a.Name, a.Description, a.HomepageURL,
		a.ClientType, a.RedirectURIs, a.RequestedPerms, a.Status,
	), "应用")
	if err != nil {
		return err
	}
	if created == nil {
		return errs.CreateAndLogInternalError(errors.New("create app returned no row"), "Failed to create app")
	}
	*a = *created
	return nil
}

// updateAppSQL 整体更新应用可管理字段，并使用 updated_at 做乐观锁。
const updateAppSQL = `
UPDATE oauth_apps
SET
    namespace       = $2,
    owner_user_id   = $3,
    secret_hash     = $4,
    name            = $5,
    description     = $6,
    homepage_url    = $7,
    client_type     = $8,
    redirect_uris   = $9,
    requested_perms = $10
WHERE id = $1 AND deleted_at IS NULL AND updated_at = $11
RETURNING ` + appColumns

const appExistsSQL = `SELECT EXISTS (SELECT 1 FROM oauth_apps WHERE id = $1 AND deleted_at IS NULL)`

// updateGrantNamespaceSQL 把以旧命名空间开头的直接授权改写为新命名空间。
// 注意：必须按 ":" 精确切分，不能用 LIKE，因为命名空间允许下划线（LIKE 通配符）。
const updateGrantNamespaceSQL = `
UPDATE user_permission_grants
SET permission = $2 || substr(permission, length($1) + 1)
WHERE split_part(permission, ':', 1) = $1
`

// updateAuthorizationNamespaceSQL 改写 OAuth 授权记录中的权限数组。
const updateAuthorizationNamespaceSQL = `
UPDATE oauth_authorizations
SET permissions = COALESCE(
    (
        SELECT array_agg(
            CASE
                WHEN split_part(p, ':', 1) = $1
                    THEN $2 || substr(p, length($1) + 1)
                ELSE p
            END
        )
        FROM unnest(permissions) AS t(p)
    ),
    '{}'
)
WHERE EXISTS (
    SELECT 1 FROM unnest(permissions) AS t(p)
    WHERE split_part(p, ':', 1) = $1
)
`

// updateRequestedPermsNamespaceSQL 改写全部应用申请权限中的旧命名空间，保持申请意图。
const updateRequestedPermsNamespaceSQL = `
UPDATE oauth_apps
SET requested_perms = COALESCE(
    (
        SELECT array_agg(
            CASE
                WHEN split_part(p, ':', 1) = $1
                    THEN $2 || substr(p, length($1) + 1)
                ELSE p
            END
        )
        FROM unnest(requested_perms) AS t(p)
    ),
    '{}'
)
WHERE EXISTS (
    SELECT 1 FROM unnest(requested_perms) AS t(p)
    WHERE split_part(p, ':', 1) = $1
)
`

// UpdateApp 整体更新应用字段：oldNamespace 用于在命名空间变化时级联改写授权中的权限串。
// expectedUpdatedAt 须为调用方读取应用时的 updated_at 原值（乐观锁），不一致时返回 409。
// 命名空间变化后触发权限目录异步重载。
func UpdateApp(
	ctx context.Context,
	a *model.OAuthApp,
	oldNamespace string,
	expectedUpdatedAt time.Time,
) *errs.Error {
	if a == nil {
		return errs.BadRequestError().AppendDetails("未提供参数")
	}
	if a.RedirectURIs == nil {
		a.RedirectURIs = []string{}
	}
	if a.RequestedPerms == nil {
		a.RequestedPerms = []string{}
	}
	if !a.ClientType.IsConfidential() {
		a.SecretHash = null.String{}
	}

	tx, err := db.R.Begin(ctx)
	if err != nil {
		return errs.CreatePGError(err, "应用", "Failed to begin transaction")
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	updated, e := scanApp(tx.QueryRow(ctx, updateAppSQL,
		a.ID, a.Namespace, a.OwnerUserID, a.SecretHash, a.Name, a.Description, a.HomepageURL,
		a.ClientType, a.RedirectURIs, a.RequestedPerms, expectedUpdatedAt,
	), "应用")
	if e != nil {
		return e
	}
	if updated == nil {
		var exists bool
		if qErr := tx.QueryRow(ctx, appExistsSQL, a.ID).Scan(&exists); qErr != nil {
			return errs.CreatePGError(qErr, "应用", "Failed to check app existence")
		}
		if exists {
			return errs.ConflictError().AppendDetails("应用已被修改，请刷新后重试")
		}
		return errs.NotFoundError().AppendDetails("应用不存在")
	}

	// 命名空间变化时级联改写所有以旧命名空间开头的权限串
	if updated.Namespace != oldNamespace {
		if _, e := tx.Exec(ctx, updateGrantNamespaceSQL, oldNamespace, updated.Namespace); e != nil {
			return errs.CreatePGError(e, "应用授权", "Failed to cascade grant namespace")
		}
		if _, e := tx.Exec(ctx, updateAuthorizationNamespaceSQL, oldNamespace, updated.Namespace); e != nil {
			return errs.CreatePGError(e, "应用授权", "Failed to cascade authorization namespace")
		}
		if _, e := tx.Exec(ctx, updateRequestedPermsNamespaceSQL, oldNamespace, updated.Namespace); e != nil {
			return errs.CreatePGError(e, "应用", "Failed to cascade requested perms namespace")
		}

		// 级联可能再次修改当前应用（requested_perms 命中旧命名空间），重新读取以保证返回值最新
		refetched, e := scanApp(tx.QueryRow(ctx, getAppByIDSQL, a.ID), "应用")
		if e != nil {
			return e
		}
		if refetched == nil {
			return errs.NotFoundError().AppendDetails("应用不存在")
		}
		updated = refetched
	}

	if e := tx.Commit(ctx); e != nil {
		return errs.CreatePGError(e, "应用", "Failed to commit transaction")
	}

	*a = *updated
	if updated.Namespace != oldNamespace {
		perm.NotifyReload()
	}
	return nil
}

// setAppStatusSQL 更新应用状态并回填最新记录。
const setAppStatusSQL = `
UPDATE oauth_apps
SET status = $2
WHERE id = $1 AND deleted_at IS NULL
RETURNING ` + appColumns

// deleteAppRefreshTokensSQL 删除应用全部授权记录下的刷新令牌。
const deleteAppRefreshTokensSQL = `
DELETE FROM oauth_refresh_tokens
WHERE auth_id IN (SELECT id FROM oauth_authorizations WHERE app_id = $1)
`

// SetAppStatus 管理员设置应用状态；停用时同时删除刷新令牌，使应用立即失去续期能力。
// 应用状态影响权限目录，成功后触发异步重载。
func SetAppStatus(ctx context.Context, appID int64, status model.AppStatus) (*model.OAuthApp, *errs.Error) {
	tx, err := db.R.Begin(ctx)
	if err != nil {
		return nil, errs.CreatePGError(err, "应用", "Failed to begin transaction")
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	a, e := scanApp(tx.QueryRow(ctx, setAppStatusSQL, appID, status), "应用")
	if e != nil {
		return nil, e
	}
	if a == nil {
		return nil, errs.NotFoundError().AppendDetails("应用不存在")
	}

	if status == model.AppStatusSuspended {
		if _, e := tx.Exec(ctx, deleteAppRefreshTokensSQL, appID); e != nil {
			return nil, errs.CreatePGError(e, "应用", "Failed to revoke app refresh tokens")
		}
	}

	if e := tx.Commit(ctx); e != nil {
		return nil, errs.CreatePGError(e, "应用", "Failed to commit transaction")
	}

	perm.NotifyReload()
	return a, nil
}

// deleteAppSQL 软删除应用并回填删除前的记录。
const deleteAppSQL = `
UPDATE oauth_apps
SET deleted_at = now()
WHERE id = $1 AND deleted_at IS NULL
RETURNING ` + appColumns

// deleteAppAuthorizationsSQL 删除应用的全部用户授权，刷新令牌随外键级联删除。
const deleteAppAuthorizationsSQL = `DELETE FROM oauth_authorizations WHERE app_id = $1`

// deleteAppGrantsSQL 删除由该应用发起的直接授权，以及旧命名空间下的全部授权。
// 命名空间在应用软删除后可被新应用复用，必须清理旧授权避免新应用继承历史授权。
const deleteAppGrantsSQL = `
DELETE FROM user_permission_grants
WHERE granted_by_app_id = $1 OR split_part(permission, ':', 1) = $2
`

// scrubAuthorizationNamespaceSQL 从其他应用的 OAuth 授权中移除旧命名空间的权限。
const scrubAuthorizationNamespaceSQL = `
UPDATE oauth_authorizations
SET permissions = COALESCE(
    (
        SELECT array_agg(p)
        FROM unnest(permissions) AS t(p)
        WHERE split_part(p, ':', 1) <> $1
    ),
    '{}'
)
WHERE EXISTS (
    SELECT 1 FROM unnest(permissions) AS t(p)
    WHERE split_part(p, ':', 1) = $1
)
`

// scrubRequestedPermsNamespaceSQL 从全部应用的申请权限中移除旧命名空间的权限。
const scrubRequestedPermsNamespaceSQL = `
UPDATE oauth_apps
SET requested_perms = COALESCE(
    (
        SELECT array_agg(p)
        FROM unnest(requested_perms) AS t(p)
        WHERE split_part(p, ':', 1) <> $1
    ),
    '{}'
)
WHERE EXISTS (
    SELECT 1 FROM unnest(requested_perms) AS t(p)
    WHERE split_part(p, ':', 1) = $1
)
`

// DeleteApp 管理员软删除应用：同时删除用户授权、相关直接授权与刷新令牌，权限目录随后重载。
// 返回删除前的应用记录，供调用方清理外部资源。
func DeleteApp(ctx context.Context, appID int64) (*model.OAuthApp, *errs.Error) {
	tx, err := db.R.Begin(ctx)
	if err != nil {
		return nil, errs.CreatePGError(err, "应用", "Failed to begin transaction")
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	a, e := scanApp(tx.QueryRow(ctx, deleteAppSQL, appID), "应用")
	if e != nil {
		return nil, e
	}
	if a == nil {
		return nil, errs.NotFoundError().AppendDetails("应用不存在")
	}

	if _, e := tx.Exec(ctx, deleteAppAuthorizationsSQL, appID); e != nil {
		return nil, errs.CreatePGError(e, "应用", "Failed to delete app authorizations")
	}
	if _, e := tx.Exec(ctx, deleteAppGrantsSQL, appID, a.Namespace); e != nil {
		return nil, errs.CreatePGError(e, "应用", "Failed to delete app grants")
	}
	if _, e := tx.Exec(ctx, scrubAuthorizationNamespaceSQL, a.Namespace); e != nil {
		return nil, errs.CreatePGError(e, "应用", "Failed to scrub authorization namespace")
	}
	if _, e := tx.Exec(ctx, scrubRequestedPermsNamespaceSQL, a.Namespace); e != nil {
		return nil, errs.CreatePGError(e, "应用", "Failed to scrub requested perms namespace")
	}

	if e := tx.Commit(ctx); e != nil {
		return nil, errs.CreatePGError(e, "应用", "Failed to commit transaction")
	}

	perm.NotifyReload()
	return a, nil
}

// rotateAppSecretSQL 覆盖应用密钥哈希。
const rotateAppSecretSQL = `UPDATE oauth_apps SET secret_hash = $2 WHERE id = $1 AND deleted_at IS NULL`

// GenerateClientSecret 生成 64 位随机客户端密钥，并返回明文与 SHA-512 哈希。
// 明文只在创建或重置响应中返回一次，数据库只保存哈希。
func GenerateClientSecret() (string, string, *errs.Error) {
	secret, e := crypto.GenerateCode(64, crypto.TokenCharset)
	if e != nil {
		return "", "", errs.CreateAndLogInternalError(e, "Failed to generate client secret").AppendDetails("客户端密钥生成失败")
	}
	return secret, crypto.HashSHA512(secret), nil
}

// RotateAppSecret 生成并写入新客户端密钥，返回明文（仅此一次）。
func RotateAppSecret(ctx context.Context, appID int64) (string, *errs.Error) {
	secret, hash, err := GenerateClientSecret()
	if err != nil {
		return "", err
	}

	tag, e := db.R.Exec(ctx, rotateAppSecretSQL, appID, hash)
	if e != nil {
		return "", errs.CreatePGError(e, "应用", "Failed to rotate app secret")
	}
	if tag.RowsAffected() == 0 {
		return "", errs.NotFoundError().AppendDetails("应用不存在")
	}
	return secret, nil
}
