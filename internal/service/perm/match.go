package perm

import (
	"sort"
)

func Contains(s []string, target string) bool {
	i := sort.Search(len(s), func(i int) bool { return s[i] >= target })
	return i < len(s) && s[i] == target
}

func ContainsAny(s []string, targets ...string) bool {
	for _, target := range targets {
		if Contains(s, target) {
			return true
		}
	}
	return false
}

func ContainsAll(s []string, targets ...string) bool {
	for _, target := range targets {
		if !Contains(s, target) {
			return false
		}
	}
	return true
}
