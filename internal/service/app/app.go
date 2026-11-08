// Package app 提供 OAuth 应用的只读查询服务，供权限管理、登录签发令牌（owned_apps 声明）等模块复用。
// 应用写操作与 OAuth 授权流程不在本包实现。
package app

import (
	"context"
	"errors"

	"fdfz-student-id/internal/db"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"

	"github.com/jackc/pgx/v5"
)

// ---------------------------------------------------------------------------
// 应用查询（供权限管理 / OAuth 相关模块复用）
// ---------------------------------------------------------------------------

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
	rows, e := db.R.Query(ctx, listAllAppsSQL)
	if e != nil {
		return nil, errs.CreatePGError(e, "应用", "Failed to list apps").AppendDetails("应用列表获取失败")
	}
	defer rows.Close()

	apps := make([]*model.OAuthApp, 0)
	for rows.Next() {
		a, err := scanApp(rows, "应用")
		if err != nil {
			return nil, err
		}
		apps = append(apps, a)
	}
	if e := rows.Err(); e != nil {
		return nil, errs.CreatePGError(e, "应用", "Failed to iterate apps").AppendDetails("应用列表获取失败")
	}
	return apps, nil
}
