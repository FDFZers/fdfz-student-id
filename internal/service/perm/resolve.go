package perm

import (
	"fmt"
	"maps"
	"sort"
	"strings"
)

// MatchAll 是核心解析函数。
// 它的作用是：根据用户拥有的权限模式列表（可能包含通配符 * 或 **），
// 结合系统中已定义的权限及其继承关系，计算出该用户实际拥有的所有确切权限。
func MatchAll(userPerm []string) []string {
	// 1. 预处理：构建索引以加速匹配
	// defByFirst: 按照权限定义的第一个节点作为 key 进行分组
	defByFirst := make(map[string][]PermissionDef)
	// defFirstPlaceholder: 收集那些第一个节点就是占位符（如 {school_id}）的权限定义
	var defFirstPlaceholder []PermissionDef

	for _, kp := range PermissionDefs {
		if len(kp.Nodes) == 0 {
			continue
		}
		first := kp.Nodes[0]
		// 如果第一个节点是占位符，单独存放；否则按第一个节点的具体字符串进行索引
		if IsNodePlaceholder(first) {
			defFirstPlaceholder = append(defFirstPlaceholder, kp)
		} else {
			defByFirst[first] = append(defByFirst[first], kp)
		}
	}

	// defByKey: 用于通过字符串形式的权限（如 "a.b.c"）快速找回对应的权限定义对象
	defByKey := make(map[string]PermissionDef)
	// placeholderSets: 记录某个权限在不同匹配路径下收集到的所有占位符集合
	placeholderSets := make(map[string][]PlaceholderInfo)
	// seen: 用于去重的哈希表，防止同一个权限+相同的占位符组合被重复处理
	seen := make(map[string]struct{})

	// 2. 定义 DFS (深度优先搜索) 函数：遍历并解析权限的继承树 (父权限)
	var visit func(kp PermissionDef, inherited PlaceholderInfo, stack map[string]bool)
	visit = func(kp PermissionDef, inherited PlaceholderInfo, stack map[string]bool) {
		permKey := NodesToPerm(kp.Nodes)
		// 防止循环继承导致死循环 (例如 A 继承 B, B 继承 A)
		if stack[permKey] {
			return
		}
		stack[permKey] = true
		defer delete(stack, permKey) // 回溯时移出栈

		// 合并占位符：创建一个新的 map，优先把当前权限自身定义的占位符初始化为 "*" (代表拥有该占位符的全部权限)
		merged := make(PlaceholderInfo, len(kp.Placeholders)+len(inherited))
		for _, name := range kp.Placeholders {
			merged[name] = "*"
		}
		// 将从子节点继承来的占位符具体值覆盖进去
		maps.Copy(merged, inherited)

		// 提取当前权限自身需要的占位符信息，存入 res
		res := make(PlaceholderInfo, len(kp.Placeholders))
		for _, name := range kp.Placeholders {
			res[name] = merged[name]
		}

		defByKey[permKey] = kp

		// 使用 "权限名::占位符序列化字符串" 作为唯一键来进行全局去重
		dedupKey := permKey + "::" + placeholdersKey(res)
		if _, ok := seen[dedupKey]; !ok {
			seen[dedupKey] = struct{}{}
			// 将有效的占位符组合加入集合，后续会进行合并化简
			placeholderSets[permKey] = append(placeholderSets[permKey], res)
		}

		// 递归遍历所有的父权限（即因为拥有当前权限，从而自动拥有的上一级权限）
		for _, parent := range kp.Parents {
			visit(*parent, merged, stack)
		}
	}

	// 3. 处理用户传入的权限列表
	seenUser := make(map[string]struct{}, len(userPerm))
	for _, up := range userPerm {
		// 过滤重复的用户权限输入
		if _, ok := seenUser[up]; ok {
			continue
		}
		seenUser[up] = struct{}{}

		uNodes := GetNodes(up)

		// 根据用户权限的第一个节点，初步筛选出可能匹配的权限定义（避免全量遍历，提升性能）
		var candidates []PermissionDef
		if len(uNodes) == 0 {
			candidates = PermissionDefs
		} else {
			switch uNodes[0] {
			case "*", "**": // 如果上来就是通配符，只能老老实实遍历所有定义的权限
				candidates = PermissionDefs
			default: // 否则只看首节点匹配的，以及首节点是占位符的定义
				candidates = append(candidates, defByFirst[uNodes[0]]...)
				candidates = append(candidates, defFirstPlaceholder...)
			}
		}

		// 核心校验：测试用户的权限字符串能否匹配这些候选权限定义
		for _, kp := range candidates {
			if ph, ok := matchPermNodes(uNodes, kp.Nodes, 0, 0, make(PlaceholderInfo)); ok {
				// 如果匹配成功，触发 DFS 遍历去获取它及其所有父权限
				visit(kp, ph, make(map[string]bool))
			}
		}
	}

	// 4. 汇总整理输出结果
	out := make(map[string]struct{})
	for permKey, sets := range placeholderSets {
		def := defByKey[permKey]

		// 如果该权限本身没有占位符，直接加入结果集
		if len(def.Placeholders) == 0 {
			out[permKey] = struct{}{}
			continue
		}

		// 尝试合并该权限的多个占位符集合（例如将 {id:1} 和 {id:*} 合并为更宽泛的 {id:*}）
		merged, err := mergePlaceholders(def.Nodes, sets)
		if err != nil {
			continue
		}
		// 根据合并后的占位符，将其回填入权限节点生成最终的确切权限字符串
		for _, ph := range merged {
			out[NodesToPerm(FillPlaceholders(def.Nodes, ph))] = struct{}{}
		}
	}

	// 将 map 转换为按字典序排序的切片返回
	result := make([]string, 0, len(out))
	for s := range out {
		result = append(result, s)
	}
	sort.Strings(result)
	return result
}

type PermissionMatch struct {
	Def             *PermissionDef
	PlaceholderInfo PlaceholderInfo
}

// ResolvePerm 用于精确解析单个权限字符串（不带通配符的实例），
// 找到它匹配的权限定义，并提取出里面的占位符取值。
func ResolvePerm(perm string) []PermissionMatch {
	permNodes := GetNodes(perm)
	var matches []PermissionMatch
	for i := range PermissionDefs {
		def := &PermissionDefs[i]
		// 检查长度并提取占位符，如果结构一致则代表匹配成功
		if ph, ok := extractPlaceholders(def.Nodes, permNodes); ok {
			matches = append(matches, PermissionMatch{Def: def, PlaceholderInfo: ph})
		}
	}
	return matches
}

// extractPlaceholders 是 ResolvePerm 的辅助函数。
// 用于比对定义节点和实际节点，将定义中的 {xxx} 替换为实际节点的值并提取出来。
func extractPlaceholders(defNodes, permNodes []string) (PlaceholderInfo, bool) {
	if len(defNodes) != len(permNodes) {
		return nil, false
	}
	ph := make(PlaceholderInfo)
	for i, dn := range defNodes {
		pn := permNodes[i]
		if IsNodePlaceholder(dn) { // 如果定义中这是一个占位符，记录下它对应的值
			ph[dn[1:len(dn)-1]] = pn
		} else if dn != pn { // 如果是普通节点，则必须完全相等
			return nil, false
		}
	}
	return ph, true
}

// matchPermNodes 是非常核心的匹配算法（双指针 + 递归回溯）。
// u 代表用户输入的权限节点 (可能包含 *, **)
// d 代表系统定义的权限节点 (可能包含占位符 {xxx})
func matchPermNodes(u, d []string, uIndex, dIndex int, placeholders PlaceholderInfo) (PlaceholderInfo, bool) {
	// 如果用户节点用完了，看看定义节点是不是也恰好匹配完了
	if uIndex >= len(u) {
		return placeholders, true
	}
	// 如果定义节点用完但用户节点还有，说明不匹配
	if dIndex >= len(d) {
		return nil, false
	}

	uNode := u[uIndex]
	dNode := d[dIndex]

	// 算法核心分支 1：处理 '**' 通配符 (匹配零个或多个节点)
	if uNode == "**" {
		// 尝试所有可能的匹配长度。
		// 让 '**' 匹配掉 d 中 1 个、2 个... 直到末尾的所有节点，并递归检测后续节点是否能匹配。
		// 这是一个典型的回溯思想。
		for i := dIndex + 1; i <= len(d); i++ {
			if ph, ok := matchPermNodes(u, d, uIndex+1, i, copyPlaceholders(placeholders)); ok {
				return ph, true
			}
		}
		return nil, false
	}

	// 算法核心分支 2：处理 '*' 通配符 (单节点匹配) 或 精确的文本相等
	if uNode == "*" || uNode == dNode {
		// 直接双指针各往前走一步继续匹配
		return matchPermNodes(u, d, uIndex+1, dIndex+1, placeholders)
	}

	// 算法核心分支 3：处理系统定义中的占位符 '{xxx}'
	if IsNodePlaceholder(dNode) {
		name := dNode[1 : len(dNode)-1]
		// 如果之前这个占位符已经绑过值了，且当前用户节点的值与之前绑定的值冲突，则匹配失败
		if old, ok := placeholders[name]; ok && old != uNode {
			return nil, false
		}
		// 记录新的占位符绑定关系，并继续递归匹配
		newPlaceholders := copyPlaceholders(placeholders)
		newPlaceholders[name] = uNode
		return matchPermNodes(u, d, uIndex+1, dIndex+1, newPlaceholders)
	}

	// 都不满足，说明这两个节点彻底不匹配
	return nil, false
}

// mergePlaceholders 用于简化和化简多个占位符集合（包含集合的覆盖逻辑）。
// 比如用户同时拥有 "user.delete.1" 和 "user.delete.*"，该函数会将它们合并并只保留宽泛的 "*"。
func mergePlaceholders(nodes []string, placeholders []PlaceholderInfo) ([]PlaceholderInfo, error) {
	dPlaceholders := GetPlaceholders(nodes)
	for _, p := range placeholders {
		if len(p) != len(dPlaceholders) {
			return nil, fmt.Errorf("invalid placeholders for permission %s", strings.Join(nodes, "."))
		}
	}

	// 内部函数：测试集合 A 和集合 B 的覆盖关系 (子集概念)
	mergePair := func(a, b PlaceholderInfo) ([]PlaceholderInfo, bool) {
		aSubsumesB := true // 假设 A 包含 B
		bSubsumesA := true // 假设 B 包含 A

		for _, name := range dPlaceholders {
			if a[name] != b[name] {
				// 如果 A 不是宽泛的 "*" 且与 B 不同，则 A 无法覆盖 B
				if a[name] != "*" {
					aSubsumesB = false
				}
				if b[name] != "*" {
					bSubsumesA = false
				}
			}
		}

		if aSubsumesB {
			return []PlaceholderInfo{a}, true // A 包含了 B，只需保留 A
		}
		if bSubsumesA {
			return []PlaceholderInfo{b}, true // B 包含了 A，只需保留 B
		}

		return nil, false // 互不包含，无法合并
	}

	// 外层使用贪心策略，不断两两尝试合并，直到没有任何两个集合可以被合并为止
	for {
		merged := false
		for i := 0; i < len(placeholders)-1; i++ {
			res, ok := mergePair(placeholders[i], placeholders[i+1])
			if ok {
				// 将被合并的两个元素移出，将合并后的新元素插入
				placeholders = append(placeholders[:i], placeholders[i+2:]...)
				placeholders = append(placeholders, res...)
				merged = true
				break
			}
		}
		if !merged {
			break
		}
	}

	return placeholders, nil
}

// copyPlaceholders 深拷贝字典，防止在递归（如 DFS 和回溯搜索中）对映射进行修改时污染外部的环境
func copyPlaceholders(ph PlaceholderInfo) PlaceholderInfo {
	newPh := make(PlaceholderInfo, len(ph))
	maps.Copy(newPh, ph)
	return newPh
}

// placeholdersKey 将 map 结构序列化为确定性的字符串。
// 作用：因为 map 迭代是无序的，为了给 placeholder 集合做唯一的哈希/去重判断，
// 必须先按照 key 排序再组装成统一格式的字符串 (例如 "id=1;school_id=2;")。
func placeholdersKey(ph PlaceholderInfo) string {
	if len(ph) == 0 {
		return ""
	}
	keys := make([]string, 0, len(ph))
	for k := range ph {
		keys = append(keys, k)
	}
	sort.Strings(keys) // 保证字符串结果一致性
	var sb strings.Builder
	for _, k := range keys {
		sb.WriteString(k)
		sb.WriteString("=")
		sb.WriteString(ph[k])
		sb.WriteString(";")
	}
	return sb.String()
}
