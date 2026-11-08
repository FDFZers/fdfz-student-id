package handling

import (
	"context"
	"fdfz-student-id/internal/errs"
	"fdfz-student-id/internal/model"
	"fdfz-student-id/internal/service/userperm"
	"slices"
	"strings"
)

// isWritePerm 判断权限是否属于「管理侧」写权限：student_id 应用下 users.* / permissions.*
// 命名空间中的写/改/删类权限（普通用户权限 user.*、只读管理权限 users.*.read|list 以及第三方应用权限不算）。
// 用于封禁/删除前的前置保护：避免管理员之间互相封禁/删除导致管理面瘫痪。
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

// UserHasWritePerm 判断用户当前生效的权限中是否包含管理侧写权限（users.* 或 permissions.* 的
// 写/改/删权限）。用于封禁/删除等管理操作的前置校验：不允许对拥有管理权限的账号执行，避免管理员互相
// 封禁/删除导致管理面瘫痪（权限模型当前是扁平的，没有显式的角色层级）。
// 注意：不要用 ".write" 子串判断——普通用户权限（如 user.relation.write）和第三方应用权限也会命中。
func UserHasWritePerm(ctx context.Context, userID int64) (bool, *errs.Error) {
	perms, err := userperm.ListUserEffectivePermissions(ctx, userID)
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
