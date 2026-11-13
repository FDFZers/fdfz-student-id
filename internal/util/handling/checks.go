package handling

import (
	"context"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	permsvc "fdfz-student-id/internal/service/perm"
	userpermsvc "fdfz-student-id/internal/service/userperm"
	"slices"
	"strings"
)

// isWritePerm 判断权限是否属于管理侧写权限：student_id 应用下 users.* / permissions.* 的写/改/删权限。
func isWritePerm(permission string) bool {
	value, ok := strings.CutPrefix(permission, "student_id:")
	if !ok {
		return false
	}
	if !strings.HasPrefix(value, "users.") && !strings.HasPrefix(value, "permissions.") {
		return false
	}
	return strings.Contains(value, ".write") ||
		strings.Contains(value, ".update") ||
		strings.Contains(value, ".delete")
}

// UserHasWritePerm 判断用户是否拥有管理侧写权限，用于阻止管理员互相封禁/删除。
// 不能按 ".write" 子串判断：普通用户权限和第三方应用权限也会命中。
func UserHasWritePerm(ctx context.Context, userID int64) (bool, *errs.Error) {
	perms, err := userpermsvc.ListUserEffectivePermissions(ctx, userID)
	if err != nil {
		return false, err
	}
	if slices.ContainsFunc(perms, isWritePerm) {
		return true, nil
	}
	return false, nil
}

func HasUsersNamespacePerm(claims *model.RegisteredTokenClaims) bool {
	for _, permission := range claims.Permissions {
		if strings.HasPrefix(permission, "student_id:users.") {
			return true
		}
	}
	return false
}

// IsGlobalAppAdmin 判断调用方是否拥有全局应用管理写权限（可修改命名空间与所有者）。
func IsGlobalAppAdmin(claims *model.RegisteredTokenClaims) bool {
	return permsvc.HasPermission(claims, permsvc.PermAppsUpdate)
}

// IsGlobalAppReader 判断调用方是否拥有全局应用读取权限（可读取全部应用）。
func IsGlobalAppReader(claims *model.RegisteredTokenClaims) bool {
	return permsvc.HasPermission(claims, permsvc.PermAppsList)
}
