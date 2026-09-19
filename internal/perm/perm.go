package perm

import (
	"fmt"
	"strings"

	"github.com/dlclark/regexp2"
)

var PermissionRegex = regexp2.MustCompile(`^(?:(?:[a-zA-Z-_]+|\*{1,2})\.)*(?:[a-zA-Z-_]+|\*{1,2}|{[a-zA-Z-_]+})$`, regexp2.Multiline)

type Permission struct {
	Nodes []string
}

func NewPermission(value string) (Permission, error) {
	if matches, err := PermissionRegex.MatchString(value); err != nil {
		return Permission{}, err
	} else if !matches {
		return Permission{}, fmt.Errorf("invalid permission %s", value)
	}
	return Permission{Nodes: strings.Split(value, ".")}, nil
}

func MustPermission(value string) Permission {
	p, err := NewPermission(value)
	if err != nil {
		panic(err)
	}
	return p
}

func (p Permission) String() string { return strings.Join(p.Nodes, ".") }

func (p Permission) HasWildcard() bool {
	for _, node := range p.Nodes {
		if node == "*" || node == "**" {
			return true
		}
	}
	return false
}

func (p Permission) HasPlaceholders() bool {
	for _, node := range p.Nodes {
		if strings.HasPrefix(node, "{") && strings.HasSuffix(node, "}") {
			return true
		}
	}
	return false
}

func (p Permission) Matches(other Matchable) bool {
	op, ok := other.(Permission)
	if !ok {
		return false
	}

	if p.HasPlaceholders() || op.HasWildcard() || op.HasPlaceholders() {
		return false
	}

	return matchNodes(p.Nodes, op.Nodes)
}

func matchNodes(userNodes, reqNodes []string) bool {
	if len(userNodes) == 0 {
		if len(reqNodes) == 0 {
			return true
		}
		return true
	}
	if len(reqNodes) == 0 {
		return false
	}

	userNode := userNodes[0]
	reqNode := reqNodes[0]

	switch userNode {
	case "**":
		for k := 1; k <= len(reqNodes); k++ {
			if matchNodes(userNodes[1:], reqNodes[k:]) {
				return true
			}
		}
		return false
	case "*":
		return matchNodes(userNodes[1:], reqNodes[1:])
	default:
		if userNode == reqNode {
			return matchNodes(userNodes[1:], reqNodes[1:])
		}
		return false
	}
}
