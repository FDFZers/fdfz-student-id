package perm

import (
	"fdfz-student-id/internal/model"
	"sort"
)

func contains(s []string, target string) bool {
	i := sort.Search(len(s), func(i int) bool { return s[i] >= target })
	return i < len(s) && s[i] == target
}

func containsAny(s []string, targets ...string) bool {
	for _, target := range targets {
		if contains(s, target) {
			return true
		}
	}
	return false
}

func containsAll(s []string, targets ...string) bool {
	for _, target := range targets {
		if !contains(s, target) {
			return false
		}
	}
	return true
}

func HasPermission(claims *model.RegisteredTokenClaims, permissions ...string) bool {
	if claims == nil || claims.TokenType != model.TokenTypeUser {
		return false
	}
	for _, permission := range permissions {
		if !contains(claims.Permissions, permission) {
			return false
		}
	}
	return true
}

func HasAnyPermission(claims *model.RegisteredTokenClaims, permissions ...string) bool {
	if claims == nil || claims.TokenType != model.TokenTypeUser {
		return false
	}
	return containsAny(claims.Permissions, permissions...)
}
