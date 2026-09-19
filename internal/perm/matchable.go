package perm

type Matchable interface {
	Matches(other Matchable) bool
}

type MatchableFunc struct {
	matches func(other Matchable) bool
}

func (f MatchableFunc) Matches(other Matchable) bool { return f.matches(other) }

var ALWAYS Matchable = MatchableFunc{matches: func(Matchable) bool { return true }}
var NEVER Matchable = MatchableFunc{matches: func(Matchable) bool { return false }}

func And(a, b Matchable) Matchable {
	return MatchableFunc{matches: func(other Matchable) bool {
		return a.Matches(other) && b.Matches(other)
	}}
}

func Or(a, b Matchable) Matchable {
	return MatchableFunc{matches: func(other Matchable) bool {
		return a.Matches(other) || b.Matches(other)
	}}
}

func Not(a Matchable) Matchable {
	return MatchableFunc{matches: func(other Matchable) bool {
		return !a.Matches(other)
	}}
}

func All(matchables ...Matchable) Matchable {
	return MatchableFunc{matches: func(target Matchable) bool {
		for _, m := range matchables {
			if !m.Matches(target) {
				return false
			}
		}
		return true
	}}
}

func Any(matchables ...Matchable) Matchable {
	return MatchableFunc{matches: func(target Matchable) bool {
		for _, m := range matchables {
			if m.Matches(target) {
				return true
			}
		}
		return false
	}}
}

func None(matchables ...Matchable) Matchable {
	return MatchableFunc{matches: func(target Matchable) bool {
		for _, m := range matchables {
			if m.Matches(target) {
				return false
			}
		}
		return true
	}}
}

func HasPerm(matchable Matchable, m MatchResult) bool {
	for _, single := range m {
		if matchable.Matches(single.Permission) {
			return true
		}
	}
	return false
}
