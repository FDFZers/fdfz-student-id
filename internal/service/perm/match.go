package perm

import (
	"fdfz-student-id/internal/model"
	"sort"
	"strings"
)

// 以下 contains 系列辅助函数用于在已按升序排列的 ID 切片中查找。
// claims.Permissions 保存的是权限 ID（见 ToIDs），签发时保证升序去重。

// containsID 在已排序切片 s 中二分查找 target；调用方必须保证 s 有序。
func containsID(s []int64, target int64) bool {
	i := sort.Search(len(s), func(i int) bool { return s[i] >= target })
	return i < len(s) && s[i] == target
}

func carriesPermissions(claims *model.RegisteredTokenClaims) bool {
	if claims == nil {
		return false
	}
	return claims.TokenType == model.TokenTypeUser || claims.TokenType == model.TokenTypeOAuth
}

// HasPermission 判断令牌 claims 是否同时拥有全部指定权限；提权令牌等非业务令牌一律返回 false。
// 入参为完整权限串，先按当前目录快照解析为 ID 再比对；目录中不存在（已下线）的权限视为未授予。
func HasPermission(claims *model.RegisteredTokenClaims, permissions ...string) bool {
	if !carriesPermissions(claims) {
		return false
	}
	cat := Snapshot()
	for _, permission := range permissions {
		def, ok := cat.ByString[permission]
		if !ok || !containsID(claims.Permissions, def.ID) {
			return false
		}
	}
	return true
}

// HasAnyPermission 判断令牌 claims 是否至少拥有一个指定权限；提权令牌等非业务令牌一律返回 false。
func HasAnyPermission(claims *model.RegisteredTokenClaims, permissions ...string) bool {
	if !carriesPermissions(claims) {
		return false
	}
	cat := Snapshot()
	for _, permission := range permissions {
		if def, ok := cat.ByString[permission]; ok && containsID(claims.Permissions, def.ID) {
			return true
		}
	}
	return false
}

// HasPermissionPrefix 判断令牌是否拥有任意一个以 prefix 开头的权限（如 "student_id:users."）。
// 提权令牌等非业务令牌一律返回 false。
func HasPermissionPrefix(claims *model.RegisteredTokenClaims, prefix string) bool {
	if !carriesPermissions(claims) {
		return false
	}
	cat := Snapshot()
	for _, id := range claims.Permissions {
		if def, ok := cat.ByID[id]; ok && strings.HasPrefix(def.String, prefix) {
			return true
		}
	}
	return false
}
