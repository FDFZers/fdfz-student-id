package perm

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

func WouldCreateCycle(edges map[int64][]int64, from, to int64) bool {
	if from == to {
		return true
	}
	// 加入 from -> to 后成环，等价于当前图中存在 to -> ... -> from。
	return Reaches(edges, to, from)
}

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

	for node := range edges {
		if state[node] == unvisited {
			if cycle := visit(node); cycle != nil {
				return cycle
			}
		}
	}
	return nil
}
