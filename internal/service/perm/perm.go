// Package perm 实现权限的解析与格式化、通配符匹配、权限继承图计算，以及权限目录快照的加载、原子替换与异步重载。
//
// 权限字符串形如「命名空间:value」，例如 student_id:users.list；命名空间即 oauth_apps.namespace，
// value 为 "." 分隔的节点路径。Permission 既表示具体权限，也表示可含 "*" / "**" 的模式。
package perm

import (
	"errors"
	"strings"

	"github.com/dlclark/regexp2"
)

var (
	// RegexNamespace 校验命名空间：小写字母开头，总长 2-32 位，可含小写字母、数字、下划线、连字符。
	RegexNamespace = regexp2.MustCompile(`\A[a-z][a-z0-9_-]{1,31}\z`, regexp2.None)
	// RegexNode 校验单个权限节点：1 位以上字母、数字、下划线或连字符。
	RegexNode = regexp2.MustCompile(`\A[0-9a-zA-Z_-]+\z`, regexp2.None)
	// RegexPermission 校验完整权限串：合法命名空间 + ":" + 至少一个以 "." 分隔的合法节点，不允许通配符。
	RegexPermission = regexp2.MustCompile(`\A[a-z][a-z0-9_-]{1,31}:(?:[0-9a-zA-Z_-]+\.)*[0-9a-zA-Z_-]+\z`, regexp2.None)
	// RegexPattern 校验权限模式串：结构与完整权限串相同，但每个节点可以是 "*"（单节点）或 "**"（多节点）。
	RegexPattern = regexp2.MustCompile(`\A[a-z][a-z0-9_-]{1,31}:(?:(?:[0-9a-zA-Z_-]+|\*{1,2})\.)*(?:[0-9a-zA-Z_-]+|\*{1,2})\z`, regexp2.None)
)

// Permission 表示一个权限或权限模式：Namespace 为应用命名空间，Nodes 为按 "." 拆分的 value 节点。
// 通过 ParsePattern 解析时，Nodes 中可能含通配节点 "*" 与 "**"。
type Permission struct {
	Namespace string
	Nodes     []string
}

// String 把权限渲染为「命名空间:节点.节点」形式的完整权限串。
func (p Permission) String() string {
	return Render(p.Namespace, strings.Join(p.Nodes, "."))
}

// splitNamespaceAndNodes 把完整权限串按 ":" 拆成命名空间与节点列表，并校验命名空间格式与路径非空。
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

// ParsePermission 解析严格权限串（不含通配符），返回命名空间与拆分后的节点。
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

// ParsePattern 解析权限模式串，节点中允许 "*"（匹配单个节点）与 "**"（匹配一个或多个节点）。
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

// ParseNodes 把权限 value 按 "." 拆分为节点并逐段校验；value 为空或含非法字符时返回错误。
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

// Render 把命名空间与 value 拼成完整权限串「命名空间:value」。
func Render(namespace, value string) string {
	return namespace + ":" + value
}

// HasWildcard 判断权限串是否含通配字符 "*"，用于区分具体权限与权限模式。
func HasWildcard(p string) bool {
	return strings.Contains(p, "*")
}
