package app

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	permsvc "fdfz-student-id/internal/service/perm"
	"fdfz-student-id/internal/util/crypto"
	"fdfz-student-id/internal/util/slicex"

	"github.com/guregu/null/v6"
	"github.com/jackc/pgx/v5"
)

// CoreNamespace 是内置 student_id 应用的命名空间，停用、删除或改名都会导致权限目录失效。
const CoreNamespace = "student_id"

// appColumns 是 apps 的查询列清单；顺序必须与 scanApp 的 Scan 参数一致。
const appColumns = `
id, namespace, owner_user_id, secret_hash, name, description, homepage_url,
client_type, redirect_uris, requested_perms, status,
created_at, updated_at, deleted_at
`

// scanApp 扫描一行 apps 数据；记录不存在时返回 (nil, nil)。
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

const getAppByIDSQL = `SELECT ` + appColumns + ` FROM apps WHERE id = $1 AND deleted_at IS NULL`

// GetAppByID 按 ID 返回未删除的应用（含已停用应用）；不存在时返回 (nil, nil)。
func GetAppByID(ctx context.Context, id int64) (*model.OAuthApp, *errs.Error) {
	return scanApp(db.R.QueryRow(ctx, getAppByIDSQL, id), "应用")
}

const getAppByNamespaceSQL = `SELECT ` + appColumns + ` FROM apps WHERE lower(namespace) = lower($1) AND deleted_at IS NULL`

// GetAppByNamespace 按命名空间大小写不敏感地返回未删除的应用；不存在时返回 (nil, nil)。
// 注意：应用可能处于 suspended 状态，调用方如需只接受 active 应用应自行判断 Status。
func GetAppByNamespace(ctx context.Context, namespace string) (*model.OAuthApp, *errs.Error) {
	return scanApp(db.R.QueryRow(ctx, getAppByNamespaceSQL, namespace), "应用")
}

const listOwnedAppIDsSQL = `
SELECT id FROM apps
WHERE owner_user_id = $1 AND deleted_at IS NULL AND status = 'active'
ORDER BY id
`

// ListOwnedAppIDs 返回用户名下有效应用的 ID 列表（供 /auth/claims 下发，以及应用所有者鉴权使用）。
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

const isOwnedAppSQL = `
SELECT EXISTS (
    SELECT 1 FROM apps
    WHERE id = $1 AND owner_user_id = $2 AND deleted_at IS NULL AND status = 'active'
)
`

// IsOwnedBy 判断应用是否属于指定用户且仍有效（active、未删除）。
// 访问令牌只保存权限 ID，应用所有者身份不再写入 JWT，改由该查询判定。
func IsOwnedBy(ctx context.Context, appID, userID int64) (bool, *errs.Error) {
	var owned bool
	if err := db.R.QueryRow(ctx, isOwnedAppSQL, appID, userID).Scan(&owned); err != nil {
		return false, errs.CreatePGError(err, "应用", "Failed to check app ownership").AppendDetails("应用信息获取失败")
	}
	return owned, nil
}

const listAllAppsSQL = `SELECT ` + appColumns + ` FROM apps WHERE deleted_at IS NULL ORDER BY id`

// ListAllApps 返回全部未删除的应用（含停用应用，仅建议在管理员语境下使用）。
func ListAllApps(ctx context.Context) ([]*model.OAuthApp, *errs.Error) {
	rows, err := db.R.Query(ctx, listAllAppsSQL)
	if err != nil {
		return nil, errs.CreatePGError(err, "应用", "Failed to list apps").AppendDetails("应用列表获取失败")
	}
	return collectApps(rows, "应用")
}

const createAppSQL = `
INSERT INTO apps (
    namespace, owner_user_id, secret_hash, name, description, homepage_url,
    client_type, redirect_uris, requested_perms, status
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
RETURNING ` + appColumns

// CreateApp 新建应用；命名空间唯一性由数据库部分唯一索引保证，冲突返回 conflict。
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

const updateAppSQL = `
UPDATE apps
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

const appExistsSQL = `SELECT EXISTS (SELECT 1 FROM apps WHERE id = $1 AND deleted_at IS NULL)`

const appRequestedPermsSQL = `SELECT requested_perms FROM apps WHERE id = $1`

// 命名空间允许下划线，必须按 ":" 精确切分，不能用 LIKE 前缀匹配。
const updateGrantNamespaceSQL = `
UPDATE user_permission_grants
SET permission = $2 || substr(permission, length($1) + 1)
WHERE split_part(permission, ':', 1) = $1
`

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

const updateRequestedPermsNamespaceSQL = `
UPDATE apps
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

// UpdateApp 整体更新应用；expectedUpdatedAt 为读取时的 updated_at 原值，不一致返回 409。
// 命名空间变化时级联改写授权中的权限串并触发权限目录重载。
func UpdateApp(
	ctx context.Context,
	dh db.Handle,
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

	tx, e := dh.Begin(ctx)
	if e != nil {
		return errs.CreatePGError(e, "应用", "Failed to begin transaction")
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	var oldRequestedPerms []string
	if e := tx.QueryRow(ctx, appRequestedPermsSQL, a.ID).Scan(&oldRequestedPerms); e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return errs.CreatePGError(e, "应用", "Failed to load app requested perms")
	}

	updated, err := scanApp(tx.QueryRow(ctx, updateAppSQL,
		a.ID, a.Namespace, a.OwnerUserID, a.SecretHash, a.Name, a.Description, a.HomepageURL,
		a.ClientType, a.RedirectURIs, a.RequestedPerms, expectedUpdatedAt,
	), "应用")
	if err != nil {
		return err
	}
	if updated == nil {
		var exists bool
		if e := tx.QueryRow(ctx, appExistsSQL, a.ID).Scan(&exists); e != nil {
			return errs.CreatePGError(e, "应用", "Failed to check app existence")
		}
		if exists {
			return errs.ConflictError().AppendDetails("应用已被修改，请刷新后重试")
		}
		return errs.NotFoundError().AppendDetails("应用不存在")
	}

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

		// 级联可能改写当前应用的 requested_perms，重新读取以保证返回值最新。
		refetched, err := scanApp(tx.QueryRow(ctx, getAppByIDSQL, a.ID), "应用")
		if err != nil {
			return err
		}
		if refetched == nil {
			return errs.NotFoundError().AppendDetails("应用不存在")
		}
		updated = refetched
	}

	// 申请权限变化时挂起全部授权并吊销刷新令牌，强制用户重新授权。
	if !slices.Equal(
		normalizeRequestedPerms(oldRequestedPerms, oldNamespace, updated.Namespace),
		normalizeRequestedPerms(updated.RequestedPerms, updated.Namespace, updated.Namespace),
	) {
		if _, e := tx.Exec(ctx, suspendAppAuthorizationsSQL, a.ID, model.AppAuthStatusUpdateSuspended); e != nil {
			return errs.CreatePGError(e, "应用授权", "Failed to suspend app authorizations after permission change")
		}
		if _, e := tx.Exec(ctx, deleteAppRefreshTokensSQL, a.ID); e != nil {
			return errs.CreatePGError(e, "应用授权", "Failed to revoke app refresh tokens after permission change")
		}
	}

	if e := tx.Commit(ctx); e != nil {
		return errs.CreatePGError(e, "应用", "Failed to commit transaction")
	}

	*a = *updated
	if updated.Namespace != oldNamespace {
		permsvc.NotifyReload()
	}
	return nil
}

const setAppStatusSQL = `
UPDATE apps
SET status = $2
WHERE id = $1 AND deleted_at IS NULL
RETURNING ` + appColumns

const deleteAppRefreshTokensSQL = `
DELETE FROM oauth_refresh_tokens
WHERE auth_id IN (SELECT id FROM oauth_authorizations WHERE app_id = $1)
`

// SetAppStatus 设置应用状态；状态影响权限目录，成功后触发异步重载。
func SetAppStatus(ctx context.Context, dh db.Handle, appID int64, status model.AppStatus) (*model.OAuthApp, *errs.Error) {
	tx, e := dh.Begin(ctx)
	if e != nil {
		return nil, errs.CreatePGError(e, "应用", "Failed to begin transaction")
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	a, err := scanApp(tx.QueryRow(ctx, setAppStatusSQL, appID, status), "应用")
	if err != nil {
		return nil, err
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

	permsvc.NotifyReload()
	return a, nil
}

const deleteAppSQL = `
UPDATE apps
SET deleted_at = now()
WHERE id = $1 AND deleted_at IS NULL
RETURNING ` + appColumns

// 刷新令牌随授权记录的外键级联删除。
const deleteAppAuthorizationsSQL = `DELETE FROM oauth_authorizations WHERE app_id = $1`

const suspendAppAuthorizationsSQL = `UPDATE oauth_authorizations SET status = $2 WHERE app_id = $1`

// 命名空间在软删除后可被新应用复用，必须清理旧授权以免被继承。
const deleteAppGrantsSQL = `
DELETE FROM user_permission_grants
WHERE granted_by_app_id = $1 OR split_part(permission, ':', 1) = $2
`

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

const scrubRequestedPermsNamespaceSQL = `
UPDATE apps
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

// DeleteApp 软删除应用并返回删除前记录，供调用方清理外部资源。
func DeleteApp(ctx context.Context, dh db.Handle, appID int64) (*model.OAuthApp, *errs.Error) {
	tx, e := dh.Begin(ctx)
	if e != nil {
		return nil, errs.CreatePGError(e, "应用", "Failed to begin transaction")
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	a, err := scanApp(tx.QueryRow(ctx, deleteAppSQL, appID), "应用")
	if err != nil {
		return nil, err
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

	permsvc.NotifyReload()
	return a, nil
}

const rotateAppSecretSQL = `UPDATE apps SET secret_hash = $2 WHERE id = $1 AND deleted_at IS NULL`

// GenerateClientSecret 生成客户端密钥；明文只在创建或重置响应中返回一次，数据库只保存哈希。
func GenerateClientSecret() (string, string, *errs.Error) {
	secret, err := crypto.GenerateCode(64, crypto.TokenCharset)
	if err != nil {
		return "", "", errs.CreateAndLogInternalError(err, "Failed to generate client secret").AppendDetails("客户端密钥生成失败")
	}
	return secret, crypto.HashSHA512(secret), nil
}

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

// normalizeRequestedPerms 统一新旧命名空间后排序去重，避免仅改命名空间被误判为申请权限变化。
func normalizeRequestedPerms(perms []string, fromNamespace, toNamespace string) []string {
	normalized := make([]string, 0, len(perms))
	for _, permission := range perms {
		if fromNamespace != toNamespace {
			if rest, ok := strings.CutPrefix(permission, fromNamespace+":"); ok {
				permission = toNamespace + ":" + rest
			}
		}
		normalized = append(normalized, permission)
	}
	return slicex.SortDedupe(normalized)
}
