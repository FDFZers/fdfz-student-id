package perm

import "sort"

// ResolvePatterns 把用户的有效授权（可能含 "*" / "**" 模式）按当前目录快照展开为具体权限串。
//
// 展开流程：对每个 pattern 解析出命名空间，在快照中找出同一命名空间下匹配的权限定义，
// 再沿权限继承图收集被隐含的权限，最终去重并按字典序排序（JWT claims 依赖该顺序做二分查找）。
// 无法解析的 pattern 会被静默跳过，避免历史脏数据导致登录失败。
// 注意：结果依赖当前目录快照；快照尚未加载时返回空列表。
func ResolvePatterns(patterns []string) []string {
	cat := Snapshot()

	// out: 已展开的确切权限值（去重）
	out := make(map[string]struct{})

	// visited 在本次解析内跨 pattern 共享：每个权限定义只沿继承图展开一次。
	// 权限目录加载时已校验继承图无环（见 catalog.go 的 validateCycleImplies），因此不需要
	// 路径栈做环检测；全局去重把复杂度从指数级（菱形继承）降为 O(V+E)。
	visited := make(map[int64]struct{})

	var visit func(info *PermissionInfo)
	visit = func(info *PermissionInfo) {
		if _, ok := visited[info.ID]; ok {
			return
		}
		visited[info.ID] = struct{}{}

		out[info.String] = struct{}{}

		// 递归处理 implies（拥有当前权限 ⇒ 隐含拥有被蕴含的权限）
		for _, implied := range info.Implies {
			visit(implied)
		}
	}

	for _, up := range patterns {
		pattern, err := ParsePattern(up)
		if err != nil {
			continue
		}
		for _, def := range cat.ByNamespace[pattern.Namespace] {
			if matchPermNodes(pattern.Nodes, def.Nodes, 0, 0) {
				visit(def)
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

// matchPermNodes 用回溯法匹配模式节点序列 u 与权限节点序列 d。
// "*" 匹配单个节点；"**" 匹配一个或多个节点（不匹配零个节点）；其余节点按文本精确匹配。
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
