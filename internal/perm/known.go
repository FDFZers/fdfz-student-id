package perm

import (
	"fmt"
	"maps"
	"reflect"
	"slices"
	"sort"
	"strings"

	"github.com/dlclark/regexp2"
)

type KnownPermission struct {
	Nodes   []string
	Parents []*string
}

type PermPlaceholders map[string]string
type MatchResult = []SingleMatchResult

type SingleMatchResult struct {
	Nodes        []string
	Placeholders PermPlaceholders
}

var PermissionRegex = regexp2.MustCompile(`\A(?:(?:[a-zA-Z_\-]|\*{1,2})\.)*(?:[a-zA-Z_\-]|\*{1,2})\z`, regexp2.None)

var (
	KnownPermissionsByID    map[int64]KnownPermission
	KnownPermissionsByValue map[string]KnownPermission
)

func SplitNodes(perm string) ([]string, error) {
	matches, err := PermissionRegex.MatchString(perm)
	if err != nil {
		return nil, err
	}
	if !matches {
		return nil, fmt.Errorf("invalid permission %s", perm)
	}
	nodes := strings.Split(perm, ".")
	if slices.Contains(nodes, "") {
		return nil, fmt.Errorf("invalid permission %s", perm)
	}
	return nodes, nil
}

func NodesToPerm(nodes []string) string {
	return strings.Join(nodes, ".")
}

func MatchKnown(userPerm []string) MatchResult {
	knownByFirst := make(map[string][]KnownPermission)
	var knownFirstPlaceholder []KnownPermission

	for _, kp := range KnownPermissionsByValue {
		nodes := kp.Nodes
		if len(nodes) == 0 {
			continue
		}
		first := nodes[0]
		if isPlaceholderNode(first) {
			knownFirstPlaceholder = append(knownFirstPlaceholder, kp)
			continue
		}
		knownByFirst[first] = append(knownByFirst[first], kp)
	}

	placeholderMap := make(map[string]map[string]PermPlaceholders)
	permNodesByKey := make(map[string][]string)
	added := make(map[string]bool)

	var addResult func(kp KnownPermission, placeholders PermPlaceholders, stack map[string]bool)
	addResult = func(kp KnownPermission, placeholders PermPlaceholders, stack map[string]bool) {
		permKey := NodesToPerm(kp.Nodes)

		if stack[permKey] {
			return
		}
		stack[permKey] = true
		defer delete(stack, permKey)

		key := permKey + "::" + placeholdersKey(placeholders)
		if added[key] {
			return
		}
		added[key] = true

		permPlaceholders := getPlaceholders(kp.Nodes)

		newPlaceholders := make(PermPlaceholders, len(permPlaceholders)+len(placeholders))
		for _, name := range permPlaceholders {
			newPlaceholders[name] = "*"
		}
		maps.Copy(newPlaceholders, placeholders)

		resPlaceholders := make(PermPlaceholders, len(permPlaceholders))
		for _, name := range permPlaceholders {
			resPlaceholders[name] = newPlaceholders[name]
		}

		if placeholderMap[permKey] == nil {
			placeholderMap[permKey] = make(map[string]PermPlaceholders)
			permNodesByKey[permKey] = kp.Nodes
		}
		if len(resPlaceholders) > 0 {
			phKey := placeholdersKey(resPlaceholders)
			placeholderMap[permKey][phKey] = resPlaceholders
		}

		for _, parent := range kp.Parents {
			parentKP, ok := KnownPermissionsByValue[*parent]
			if !ok {
				continue
			}
			addResult(parentKP, newPlaceholders, stack)
		}
	}

	seenUser := make(map[string]struct{}, len(userPerm))
	for _, userPerm := range userPerm {
		userKey := userPerm
		if _, ok := seenUser[userKey]; ok {
			continue
		}
		seenUser[userKey] = struct{}{}

		uNodes, err := SplitNodes(userPerm)
		if err != nil {
			continue
		}

		var candidates []KnownPermission
		if len(uNodes) == 0 {
			candidates = allKnownPermissions()
		} else {
			switch uNodes[0] {
			case "*", "**":
				candidates = allKnownPermissions()
			default:
				candidates = append(candidates, knownByFirst[uNodes[0]]...)
				candidates = append(candidates, knownFirstPlaceholder...)
			}
		}

		for _, kp := range candidates {
			ph, ok := matchPermNodes(uNodes, kp.Nodes, 0, 0, make(PermPlaceholders))
			if ok {
				addResult(kp, ph, make(map[string]bool))
			}
		}
	}

	var result MatchResult
	for permKey, phMap := range placeholderMap {
		nodes := permNodesByKey[permKey]
		if len(phMap) == 0 {
			result = append(result, SingleMatchResult{Nodes: nodes})
			continue
		}
		if len(phMap) == 1 {
			for _, ph := range phMap {
				result = append(result, SingleMatchResult{Nodes: nodes, Placeholders: ph})
			}
			continue
		}

		var phList []PermPlaceholders
		for _, ph := range phMap {
			phList = append(phList, ph)
		}

		merged, err := mergePlaceholders(nodes, phList)
		if err != nil {
			continue
		}
		for _, ph := range merged {
			result = append(result, SingleMatchResult{Nodes: nodes, Placeholders: ph})
		}
	}

	return result
}

func allKnownPermissions() []KnownPermission {
	values := make([]KnownPermission, 0, len(KnownPermissionsByValue))
	for _, kp := range KnownPermissionsByValue {
		values = append(values, kp)
	}
	return values
}

func isPlaceholderNode(node string) bool {
	return strings.HasPrefix(node, "{") && strings.HasSuffix(node, "}")
}

func getPlaceholders(nodes []string) []string {
	var res []string
	for _, node := range nodes {
		if isPlaceholderNode(node) {
			res = append(res, node[1:len(node)-1])
		}
	}
	return res
}

func placeholdersKey(ph PermPlaceholders) string {
	if len(ph) == 0 {
		return ""
	}
	keys := make([]string, 0, len(ph))
	for k := range ph {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	for _, k := range keys {
		sb.WriteString(k)
		sb.WriteString("=")
		sb.WriteString(ph[k])
		sb.WriteString(";")
	}
	return sb.String()
}

func copyPlaceholders(ph PermPlaceholders) PermPlaceholders {
	newPh := make(PermPlaceholders, len(ph))
	maps.Copy(newPh, ph)
	return newPh
}

func matchPermNodes(u, k []string, uIndex, kIndex int, placeholders PermPlaceholders) (PermPlaceholders, bool) {
	if uIndex >= len(u) {
		return placeholders, true
	}
	if kIndex >= len(k) {
		return nil, false
	}

	uNode := u[uIndex]
	kNode := k[kIndex]

	if uNode == "**" {
		for i := kIndex + 1; i <= len(k); i++ {
			if ph, ok := matchPermNodes(u, k, uIndex+1, i, copyPlaceholders(placeholders)); ok {
				return ph, true
			}
		}
		return nil, false
	}

	if uNode == "*" || uNode == kNode {
		return matchPermNodes(u, k, uIndex+1, kIndex+1, placeholders)
	}

	if isPlaceholderNode(kNode) {
		placeholderName := kNode[1 : len(kNode)-1]
		if old, ok := placeholders[placeholderName]; ok && old != uNode {
			return nil, false
		}
		newPlaceholders := copyPlaceholders(placeholders)
		newPlaceholders[placeholderName] = uNode
		return matchPermNodes(u, k, uIndex+1, kIndex+1, newPlaceholders)
	}

	return nil, false
}

func mergePlaceholders(nodes []string, placeholders []PermPlaceholders) ([]PermPlaceholders, error) {
	kPlaceholders := getPlaceholders(nodes)
	for _, p := range placeholders {
		if len(p) != len(kPlaceholders) {
			return nil, fmt.Errorf("invalid placeholders for permission %s", strings.Join(nodes, "."))
		}
	}

	mergePlaceholder := func(a, b PermPlaceholders) ([]PermPlaceholders, bool) {
		aCopy := copyPlaceholders(a)
		bCopy := copyPlaceholders(b)
		changed := false
		for i := len(kPlaceholders) - 1; i >= 0; i-- {
			placeholder := kPlaceholders[i]
			aValue := aCopy[placeholder]
			bValue := bCopy[placeholder]
			if aValue == "*" && bValue != "*" {
				bCopy[placeholder] = "*"
				changed = true
			}
			if bValue == "*" && aValue != "*" {
				aCopy[placeholder] = "*"
				changed = true
			}
			if aValue != "*" && bValue != "*" && aValue != bValue {
				break
			}
		}
		if !changed {
			return nil, false
		}
		if reflect.DeepEqual(aCopy, bCopy) {
			return []PermPlaceholders{aCopy}, true
		}
		return []PermPlaceholders{aCopy, bCopy}, true
	}

	for {
		merged := false
		for i := 0; i < len(placeholders)-1; i++ {
			res, ok := mergePlaceholder(placeholders[i], placeholders[i+1])
			if ok {
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

func MatchResultToPermStrings(result MatchResult) []string {
	if len(result) == 0 {
		return []string{}
	}

	outMap := make(map[string]struct{})
	for _, r := range result {
		if len(r.Placeholders) > 0 {
			nodes := make([]string, len(r.Nodes))
			copy(nodes, r.Nodes)

			for i, node := range nodes {
				if !isPlaceholderNode(node) {
					continue
				}

				name := node[1 : len(node)-1]
				if v, ok := r.Placeholders[name]; ok {
					nodes[i] = v
				}
			}

			r.Nodes = nodes
		}

		s := NodesToPerm(r.Nodes)
		outMap[s] = struct{}{}
	}

	out := make([]string, 0, len(outMap))
	for s := range outMap {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
