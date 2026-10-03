package perm

import (
	"sort"
)

func Contains(s []string, target string) bool {
	i := sort.Search(len(s), func(i int) bool { return s[i] >= target })
	return i < len(s) && s[i] == target
}

func ContainsAny(s []string, targets ...string) bool {
	i, j := 0, 0
	for i < len(s) && j < len(targets) {
		switch {
		case s[i] < targets[j]:
			i++
		case s[i] > targets[j]:
			j++
		default:
			return true
		}
	}
	return false
}

func ContainsAll(s []string, targets ...string) bool {
	if len(targets) == 0 {
		return true
	}
	if len(targets) > len(s) {
		return false
	}
	i, j := 0, 0
	for i < len(s) && j < len(targets) {
		if s[i] == targets[j] {
			j++
		}
		i++
	}
	return j == len(targets)
}
