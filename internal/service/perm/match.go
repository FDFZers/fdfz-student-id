package perm

import (
	"fdfz-student-id/internal/model"
	"sort"
)

// 以下 contains 系列辅助函数用于在已按字典序升序排列的字符串切片中查找。

// contains 在已排序切片 s 中二分查找 target；调用方必须保证 s 有序。
func contains(s []string, target string) bool {
	i := sort.Search(len(s), func(i int) bool { return s[i] >= target })
	return i < len(s) && s[i] == target
}

// containsAny 判断有序切片 s 是否至少包含 targets 中的一个。
func containsAny(s []string, targets ...string) bool {
	for _, target := range targets {
		if contains(s, target) {
			return true
		}
	}
	return false
}

func carriesPermissions(claims *model.RegisteredTokenClaims) bool {
	if claims == nil {
		return false
	}
	return claims.TokenType == model.TokenTypeUser || claims.TokenType == model.TokenTypeOAuth
}

// HasPermission 判断令牌 claims 是否同时拥有全部指定权限；提权令牌等非业务令牌一律返回 false。
// claims.Permissions 需已按字典序排序（由 ResolvePatterns / 签发逻辑保证），否则二分查找会漏判。
func HasPermission(claims *model.RegisteredTokenClaims, permissions ...string) bool {
	if !carriesPermissions(claims) {
		return false
	}
	for _, permission := range permissions {
		if !contains(claims.Permissions, permission) {
			return false
		}
	}
	return true
}

// HasAnyPermission 判断令牌 claims 是否至少拥有一个指定权限；提权令牌等非业务令牌一律返回 false。
// claims.Permissions 需已按字典序排序，参见 HasPermission。
func HasAnyPermission(claims *model.RegisteredTokenClaims, permissions ...string) bool {
	if !carriesPermissions(claims) {
		return false
	}
	return containsAny(claims.Permissions, permissions...)
}
