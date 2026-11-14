// Package slicex 提供切片去重等通用操作。
package slicex

import (
	"cmp"
	"slices"
)

// Dedupe 按首次出现顺序去重，始终返回非 nil 切片。
func Dedupe[T comparable](items []T) []T {
	seen := make(map[T]struct{}, len(items))
	result := make([]T, 0, len(items))
	for _, item := range items {
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		result = append(result, item)
	}
	return result
}

func DedupeStrings(items []string) []string {
	return Dedupe(items)
}

// SortDedupe 排序并去重，始终返回非 nil 切片。
func SortDedupe[T cmp.Ordered](items []T) []T {
	result := make([]T, 0, len(items))
	result = append(result, items...)
	slices.Sort(result)
	return slices.Compact(result)
}
