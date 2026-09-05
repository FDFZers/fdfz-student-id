package utils

func Intersection[T comparable](a, b []T) []T {
	var shortSlice, longSlice []T
	if len(a) <= len(b) {
		shortSlice, longSlice = a, b
	} else {
		shortSlice, longSlice = b, a
	}

	mb := make(map[T]struct{}, len(shortSlice))
	for _, x := range shortSlice {
		mb[x] = struct{}{}
	}

	seen := make(map[T]struct{})
	var result []T

	for _, x := range longSlice {
		if _, found := mb[x]; found {
			if _, exists := seen[x]; !exists {
				result = append(result, x)
				seen[x] = struct{}{}
			}
		}
	}
	return result
}

func Difference[T comparable](a, b []T) []T {
	mb := make(map[T]struct{}, len(b))
	for _, x := range b {
		mb[x] = struct{}{}
	}

	var diff []T
	for _, x := range a {
		if _, found := mb[x]; !found {
			diff = append(diff, x)
		}
	}
	return diff
}

func FindFirst[T any](slice []T, predicate func(T) bool) *T {
	for _, v := range slice {
		if predicate(v) {
			return &v
		}
	}
	return nil
}
