package oauth

import (
	"context"
	"fmt"
	"strings"

	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	permsvc "fdfz-student-id/internal/service/perm"
	userpermsvc "fdfz-student-id/internal/service/userperm"
	"fdfz-student-id/internal/util/slicex"
)

const (
	MaxPermissions = 128
)

type PermissionInfo struct {
	Permission  string `json:"permission"`
	Description string `json:"description"`
	Granted     bool   `json:"granted"`
	Reason      string `json:"reason,omitempty"`
}

// ---------------------------------------------------------------------------
// 解析与校验
// ---------------------------------------------------------------------------

func ParsePermissionParam(raw string) ([]string, *errs.Error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return []string{}, nil
	}

	seen := make(map[string]struct{})
	permissions := make([]string, 0, 4)
	for _, permission := range strings.Fields(strings.ReplaceAll(raw, ",", " ")) {
		if strings.IndexByte(permission, 0) >= 0 {
			return nil, errs.BadRequestError().AppendDetails("请求解析失败")
		}
		if _, ok := seen[permission]; ok {
			continue
		}
		seen[permission] = struct{}{}
		permissions = append(permissions, permission)
	}
	if len(permissions) > MaxPermissions {
		return nil, errs.BadRequestError().AppendDetails("申请的权限数量过多")
	}
	return permissions, nil
}

func ValidatePermissionsAgainstApp(app *model.OAuthApp, permissions []string) *errs.Error {
	if app == nil {
		return errs.BadRequestError().AppendDetails("应用不存在")
	}
	allowed := make(map[string]struct{}, len(app.RequestedPerms))
	for _, permission := range app.RequestedPerms {
		allowed[permission] = struct{}{}
	}
	for _, permission := range permissions {
		if _, ok := allowed[permission]; !ok {
			return errs.BadRequestError().AppendDetails(fmt.Sprintf("权限“%s”不在应用可申请范围内", permission))
		}
	}
	return nil
}

// ResolveRequestedPermissions 解析并校验权限；参数为空时使用应用登记的全部可申请权限。
func ResolveRequestedPermissions(app *model.OAuthApp, raw string) ([]string, *errs.Error) {
	permissions, err := ParsePermissionParam(raw)
	if err != nil {
		return nil, err
	}
	if len(permissions) == 0 {
		permissions = slicex.DedupeStrings(app.RequestedPerms)
	}
	if len(permissions) == 0 {
		return nil, errs.BadRequestError().AppendDetails("应用未登记可申请的权限")
	}
	if err := ValidatePermissionsAgainstApp(app, permissions); err != nil {
		return nil, err
	}
	return permissions, nil
}

// ---------------------------------------------------------------------------
// 授予计算
// ---------------------------------------------------------------------------

// userEffectivePermissionSet 返回展开继承后的权限，与登录令牌的判定保持一致。
func userEffectivePermissionSet(ctx context.Context, userID int64) (map[string]struct{}, *errs.Error) {
	effective, err := userpermsvc.ListUserEffectivePermissions(ctx, userID)
	if err != nil {
		return nil, err
	}
	expanded := permsvc.ResolvePatterns(effective)

	set := make(map[string]struct{}, len(expanded))
	for _, permission := range expanded {
		set[permission] = struct{}{}
	}
	return set, nil
}

func ResolvePermissionInfos(ctx context.Context, userID int64, permissions []string) ([]PermissionInfo, *errs.Error) {
	effectiveSet, err := userEffectivePermissionSet(ctx, userID)
	if err != nil {
		return nil, err
	}

	catalog := permsvc.Snapshot()
	infos := make([]PermissionInfo, 0, len(permissions))
	for _, permission := range permissions {
		info := PermissionInfo{Permission: permission, Granted: true}
		def, ok := catalog.ByString[permission]
		switch {
		case !ok:
			info.Granted = false
			info.Reason = "权限未定义或所属应用已停用"
		case !def.Requestable:
			info.Granted = false
			info.Reason = "该权限不允许应用申请"
		default:
			info.Description = def.Description
			if _, has := effectiveSet[permission]; !has {
				info.Granted = false
				info.Reason = "当前账户不具备该权限"
			}
		}
		infos = append(infos, info)
	}
	return infos, nil
}

func GrantedPermissions(infos []PermissionInfo) []string {
	permissions := make([]string, 0, len(infos))
	for _, info := range infos {
		if info.Granted {
			permissions = append(permissions, info.Permission)
		}
	}
	return slicex.SortDedupe(permissions)
}

func restrictToRequested(granted, requested []string) []string {
	allowed := make(map[string]struct{}, len(requested))
	for _, permission := range requested {
		allowed[permission] = struct{}{}
	}
	result := make([]string, 0, len(granted))
	for _, permission := range granted {
		if _, ok := allowed[permission]; ok {
			result = append(result, permission)
		}
	}
	return slicex.SortDedupe(result)
}

func effectiveGrantPermissions(ctx context.Context, userID int64, permissions []string) ([]string, *errs.Error) {
	if len(permissions) == 0 {
		return []string{}, nil
	}

	effectiveSet, err := userEffectivePermissionSet(ctx, userID)
	if err != nil {
		return nil, err
	}

	catalog := permsvc.Snapshot()
	held := make([]string, 0, len(permissions))
	for _, permission := range permissions {
		if _, has := effectiveSet[permission]; !has {
			continue
		}
		if def, ok := catalog.ByString[permission]; !ok || !def.Requestable {
			continue
		}
		held = append(held, permission)
	}

	expanded := permsvc.ResolvePatterns(held)
	result := make([]string, 0, len(expanded))
	for _, permission := range expanded {
		if def, ok := catalog.ByString[permission]; ok && def.Requestable {
			result = append(result, permission)
		}
	}
	return result, nil
}
