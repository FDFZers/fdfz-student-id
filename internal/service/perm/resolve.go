package perm

import "sort"

// ResolvePatterns 把用户的有效授权（可能含 "*" / "**" 模式）按当前目录快照展开为具体权限串。
//
// 展开流程：对每个 pattern 解析出命名空间，在快照中找出同一命名空间下匹配的权限定义，
// 再沿权限继承图收集被隐含的权限，最终去重并按字典序排序（签发令牌时再经 ToIDs 转为权限 ID）。
// 无法解析的 pattern 会被静默跳过，避免历史脏数据导致登录失败。
// 注意：结果依赖当前目录快照；快照尚未加载时返回空列表。
func ResolvePatterns(patterns []string) []string {
	cat := Snapshot()

	// out: 已展开的确切权限值（去重）
	out := make(map[string]struct{})

	// 权限目录加载时已校验继承图无环，无需路径栈；visited 跨 pattern 共享去重。
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

// ToIDs 把已展开的具体权限串（如 ResolvePatterns 的结果）映射为权限 ID，供 JWT 精简存储。
// 结果升序去重；目录中已不存在的权限被静默跳过，避免历史数据导致签发失败。
func ToIDs(permissions []string) []int64 {
	cat := Snapshot()

	seen := make(map[int64]struct{}, len(permissions))
	ids := make([]int64, 0, len(permissions))
	for _, permission := range permissions {
		def, ok := cat.ByString[permission]
		if !ok {
			continue
		}
		if _, dup := seen[def.ID]; dup {
			continue
		}
		seen[def.ID] = struct{}{}
		ids = append(ids, def.ID)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

// Strings 把权限 ID 还原为具体权限串，顺序与入参 ID 一致。
// 目录中已下线的权限 ID 会被跳过，调用方无需处理空值。
func Strings(ids []int64) []string {
	cat := Snapshot()

	result := make([]string, 0, len(ids))
	for _, id := range ids {
		if def, ok := cat.ByID[id]; ok {
			result = append(result, def.String)
		}
	}
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
