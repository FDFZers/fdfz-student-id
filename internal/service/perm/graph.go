package perm

// Reaches 判断有向图中从 start 出发能否到达 goal；start == goal 时视为可达。
// 用于权限继承图的连通性判断，图以「节点 ID → 后继节点 ID 列表」的邻接表表示。
func Reaches(edges map[int64][]int64, start, goal int64) bool {
	if start == goal {
		return true
	}

	visited := map[int64]struct{}{start: {}}
	stack := []int64{start}
	for len(stack) > 0 {
		node := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, next := range edges[node] {
			if next == goal {
				return true
			}
			if _, ok := visited[next]; ok {
				continue
			}
			visited[next] = struct{}{}
			stack = append(stack, next)
		}
	}
	return false
}

// WouldCreateCycle 判断在图中新增 from -> to 这条边（from 继承 to）是否会形成环。
// 等价于判断当前图中 to 能否沿继承边到达 from。
func WouldCreateCycle(edges map[int64][]int64, from, to int64) bool {
	if from == to {
		return true
	}
	// 加入 from -> to 后成环，等价于当前图中存在 to -> ... -> from。
	return Reaches(edges, to, from)
}

// DetectCycle 用三色标记 DFS 检测有向图中的环，返回闭合的环路径（首尾节点相同）；无环时返回 nil。
// 注意：返回的切片首尾重复，环上的权限串由调用方自行渲染。
func DetectCycle(edges map[int64][]int64) []int64 {
	const (
		unvisited = 0
		visiting  = 1
		done      = 2
	)

	state := make(map[int64]int, len(edges))
	stack := make([]int64, 0, len(edges))

	var visit func(node int64) []int64
	visit = func(node int64) []int64 {
		state[node] = visiting
		stack = append(stack, node)
		for _, next := range edges[node] {
			switch state[next] {
			case visiting:
				// 遇到仍在当前 DFS 栈上的节点，说明成环；从栈中截出环路径并补回收尾节点
				for i, n := range stack {
					if n == next {
						cycle := make([]int64, 0, len(stack)-i+1)
						cycle = append(cycle, stack[i:]...)
						return append(cycle, next)
					}
				}
				return []int64{node, next, node}
			case unvisited:
				if cycle := visit(next); cycle != nil {
					return cycle
				}
			}
		}
		stack = stack[:len(stack)-1]
		state[node] = done
		return nil
	}

	// 逐节点发起 DFS，覆盖非连通图
	for node := range edges {
		if state[node] == unvisited {
			if cycle := visit(node); cycle != nil {
				return cycle
			}
		}
	}
	return nil
}
