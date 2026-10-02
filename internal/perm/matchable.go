package perm

type MatchableFunc = func(perm string) bool

func And(a, b MatchableFunc) MatchableFunc {
	return func(perm string) bool {
		return a(perm) && b(perm)
	}
}

func Or(a, b MatchableFunc) MatchableFunc {
	return func(perm string) bool {
		return a(perm) || b(perm)
	}
}

func Not(a MatchableFunc) MatchableFunc {
	return func(perm string) bool {
		return !a(perm)
	}
}

func All(matchables ...MatchableFunc) MatchableFunc {
	return func(perm string) bool {
		for _, m := range matchables {
			if !m(perm) {
				return false
			}
		}
		return true
	}
}

func Any(matchables ...MatchableFunc) MatchableFunc {
	return func(perm string) bool {
		for _, m := range matchables {
			if m(perm) {
				return true
			}
		}
		return false
	}
}

func None(matchables ...MatchableFunc) MatchableFunc {
	return func(perm string) bool {
		for _, m := range matchables {
			if m(perm) {
				return false
			}
		}
		return true
	}
}

func Perm(perm string) MatchableFunc {
	return func(other string) bool {
		return perm == other
	}
}
