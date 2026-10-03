package perm

import "fmt"

type MatchFunc = func(perm string) bool

func And(a, b MatchFunc) MatchFunc {
	return func(perm string) bool {
		return a(perm) && b(perm)
	}
}

func Or(a, b MatchFunc) MatchFunc {
	return func(perm string) bool {
		return a(perm) || b(perm)
	}
}

func Not(a MatchFunc) MatchFunc {
	return func(perm string) bool {
		return !a(perm)
	}
}

func All(funcs ...MatchFunc) MatchFunc {
	return func(perm string) bool {
		for _, m := range funcs {
			if !m(perm) {
				return false
			}
		}
		return true
	}
}

func Any(funcs ...MatchFunc) MatchFunc {
	return func(perm string) bool {
		for _, m := range funcs {
			if m(perm) {
				return true
			}
		}
		return false
	}
}

func None(funcs ...MatchFunc) MatchFunc {
	return func(perm string) bool {
		for _, m := range funcs {
			if m(perm) {
				return false
			}
		}
		return true
	}
}

func MatchPerm(perm string) MatchFunc {
	if ok, err := RegexPerm.MatchString(perm); err != nil {
		panic(fmt.Errorf("failed to validate permission: %w", err))
	} else if !ok {
		panic(fmt.Errorf("invalid permission %s", perm))
	}
	return func(other string) bool {
		return perm == other
	}
}
