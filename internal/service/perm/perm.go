package perm

import (
	"errors"
	"strings"

	"github.com/dlclark/regexp2"
)

var (
	RegexNamespace  = regexp2.MustCompile(`\A[a-z][a-z0-9_-]{1,31}\z`, regexp2.None)
	RegexNode       = regexp2.MustCompile(`\A[0-9a-zA-Z_-]+\z`, regexp2.None)
	RegexPermission = regexp2.MustCompile(`\A[a-z][a-z0-9_-]{1,31}:(?:[0-9a-zA-Z_-]+\.)*[0-9a-zA-Z_-]+\z`, regexp2.None)
	RegexPattern    = regexp2.MustCompile(`\A[a-z][a-z0-9_-]{1,31}:(?:(?:[0-9a-zA-Z_-]+|\*{1,2})\.)*(?:[0-9a-zA-Z_-]+|\*{1,2})\z`, regexp2.None)
)

type Permission struct {
	Namespace string
	Nodes     []string
}

func (p Permission) String() string {
	return Render(p.Namespace, strings.Join(p.Nodes, "."))
}

func splitNamespaceAndNodes(s string) (string, []string, error) {
	ns, path, ok := strings.Cut(s, ":")
	if !ok {
		return "", nil, errors.New("permission must contain a namespace separator ':'")
	}
	if ok, err := RegexNamespace.MatchString(ns); err != nil || !ok {
		return "", nil, errors.New("invalid permission namespace")
	}
	if path == "" {
		return "", nil, errors.New("permission path is empty")
	}
	nodes := strings.Split(path, ".")
	return ns, nodes, nil
}

func ParsePermission(s string) (Permission, error) {
	if ok, err := RegexPermission.MatchString(s); err != nil || !ok {
		return Permission{}, errors.New("invalid permission")
	}
	ns, nodes, err := splitNamespaceAndNodes(s)
	if err != nil {
		return Permission{}, err
	}
	return Permission{Namespace: ns, Nodes: nodes}, nil
}

func ParsePattern(s string) (Permission, error) {
	if ok, err := RegexPattern.MatchString(s); err != nil || !ok {
		return Permission{}, errors.New("invalid permission pattern")
	}
	ns, nodes, err := splitNamespaceAndNodes(s)
	if err != nil {
		return Permission{}, err
	}
	return Permission{Namespace: ns, Nodes: nodes}, nil
}

func ParseNodes(value string) ([]string, error) {
	if value == "" {
		return nil, errors.New("permission value is empty")
	}
	nodes := strings.Split(value, ".")
	for _, node := range nodes {
		if ok, err := RegexNode.MatchString(node); err != nil || !ok {
			return nil, errors.New("invalid permission value")
		}
	}
	return nodes, nil
}

func Render(namespace, value string) string {
	return namespace + ":" + value
}

func HasWildcard(p string) bool {
	return strings.Contains(p, "*")
}
