package perm

import "sort"

func ResolvePatterns(patterns []string) []string {
	cat := Snapshot()

	// out: 已展开的确切权限值（去重）
	out := make(map[string]struct{})

	var visit func(info *PermissionInfo, stack map[int64]bool)
	visit = func(info *PermissionInfo, stack map[int64]bool) {
		// 防止循环继承导致死循环（例如 A 继承 B，B 继承 A）
		if stack[info.ID] {
			return
		}
		stack[info.ID] = true
		defer delete(stack, info.ID)

		out[info.String] = struct{}{}

		// 递归处理 implies（拥有当前权限 ⇒ 隐含拥有被蕴含的权限）
		for _, implied := range info.Implies {
			visit(implied, stack)
		}
	}

	for _, up := range patterns {
		pattern, err := ParsePattern(up)
		if err != nil {
			// 无效授权 pattern 不应破坏整体解析（可能是历史脏数据），静默跳过。
			continue
		}
		for _, def := range cat.ByNamespace[pattern.Namespace] {
			if matchPermNodes(pattern.Nodes, def.Nodes, 0, 0) {
				visit(def, make(map[int64]bool))
			}
		}
	}

	result := make([]string, 0, len(out))
	for v := range out {
		result = append(result, v)
	}
	sort.Strings(result)
	return result
}

func matchPermNodes(u, d []string, uIndex, dIndex int) bool {
	if uIndex >= len(u) {
		return dIndex >= len(d)
	}
	if dIndex >= len(d) {
		return false
	}

	uNode := u[uIndex]

	// ** 匹配一个或多个节点
	if uNode == "**" {
		for i := dIndex + 1; i <= len(d); i++ {
			if matchPermNodes(u, d, uIndex+1, i) {
				return true
			}
		}
		return false
	}

	// * 匹配单个节点，或精确文本匹配
	if uNode == "*" || uNode == d[dIndex] {
		return matchPermNodes(u, d, uIndex+1, dIndex+1)
	}

	return false
}
