package perm

import (
	"strings"

	"github.com/dlclark/regexp2"
)

type PlaceholderInfo map[string]string

var (
	RegexPerm           = regexp2.MustCompile(`\A(?:[0-9a-zA-Z_-]+\.)*[0-9a-zA-Z_-]+\z`, regexp2.None)
	RegexPermUser       = regexp2.MustCompile(`\A(?:(?:[0-9a-zA-Z_-]+|\*{1,2})\.)*(?:[0-9a-zA-Z_-]+|\*{1,2})\z`, regexp2.None)
	RegexPermDefinition = regexp2.MustCompile(`\A(?:(?:[0-9a-zA-Z_-]+|\{[0-9a-zA-Z_-]+})\.)*(?:[0-9a-zA-Z_-]+|\{[0-9a-zA-Z_-]+})\z`, regexp2.None)
)

func GetNodes(p string) []string {
	return strings.Split(p, ".")
}

func NodesToPerm(n []string) string {
	return strings.Join(n, ".")
}

func HasWildcard(p string) bool {
	return strings.Contains(p, "*")
}

func HasPlaceholder(p string) bool {
	return strings.Contains(p, "{")
}

func IsNodePlaceholder(node string) bool {
	return strings.HasPrefix(node, "{") && strings.HasSuffix(node, "}")
}

func GetPlaceholders(nodes []string) []string {
	seen := make(map[string]struct{})
	var res []string
	for _, node := range nodes {
		if IsNodePlaceholder(node) {
			name := node[1 : len(node)-1]
			if _, ok := seen[name]; !ok {
				seen[name] = struct{}{}
				res = append(res, name)
			}
		}
	}
	return res
}

func FillPlaceholders(nodes []string, placeholders PlaceholderInfo) []string {
	var res = make([]string, 0, len(nodes))
	for _, node := range nodes {
		if IsNodePlaceholder(node) {
			name := node[1 : len(node)-1]
			if placeholder, ok := placeholders[name]; ok {
				res = append(res, placeholder)
				continue
			}
		}
		res = append(res, node)
	}
	return res
}
