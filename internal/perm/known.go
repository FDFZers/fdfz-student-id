package perm

import (
	"fmt"
	"maps"
	"reflect"
	"sort"
	"strings"
)

type KnownPermission struct {
	Permission
	Parents []*Permission
}

var (
	KnownPermissionsByID    map[int64]KnownPermission
	KnownPermissionsByValue map[string]KnownPermission
)

type PermPlaceholders map[string]string
type MatchResult = []SingleMatchResult

type SingleMatchResult struct {
	Permission   Permission
	Placeholders PermPlaceholders
}

func MatchKnown(userPermissions []Permission) MatchResult {
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
	permByKey := make(map[string]Permission)
	added := make(map[string]bool)

	var addResult func(kp KnownPermission, placeholders PermPlaceholders)
	addResult = func(kp KnownPermission, placeholders PermPlaceholders) {
		permission := kp.Permission
		permKey := permission.String()

		key := permKey + "::" + placeholdersKey(placeholders)
		if added[key] {
			return
		}
		added[key] = true

		permPlaceholders := getPlaceholders(permission.Nodes)

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
			permByKey[permKey] = permission
		}
		if len(resPlaceholders) > 0 {
			phKey := placeholdersKey(resPlaceholders)
			placeholderMap[permKey][phKey] = resPlaceholders
		}

		for _, parent := range kp.Parents {
			parentKP, ok := KnownPermissionsByValue[parent.String()]
			if !ok {
				continue
			}
			addResult(parentKP, newPlaceholders)
		}
	}

	seenUser := make(map[string]struct{}, len(userPermissions))
	for _, userPerm := range userPermissions {
		userKey := userPerm.String()
		if _, ok := seenUser[userKey]; ok {
			continue
		}
		seenUser[userKey] = struct{}{}

		uNodes := userPerm.Nodes

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
				addResult(kp, ph)
			}
		}
	}

	var result MatchResult
	for permKey, phMap := range placeholderMap {
		permission := permByKey[permKey]
		if len(phMap) == 0 {
			result = append(result, SingleMatchResult{Permission: permission})
			continue
		}
		if len(phMap) == 1 {
			for _, ph := range phMap {
				result = append(result, SingleMatchResult{Permission: permission, Placeholders: ph})
			}
			continue
		}

		var phList []PermPlaceholders
		for _, ph := range phMap {
			phList = append(phList, ph)
		}

		merged, err := mergePlaceholders(permission.Nodes, phList)
		if err != nil {
			continue
		}
		for _, ph := range merged {
			result = append(result, SingleMatchResult{Permission: permission, Placeholders: ph})
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
		changed := false
		for i := len(kPlaceholders) - 1; i >= 0; i-- {
			placeholder := kPlaceholders[i]
			aValue := a[placeholder]
			bValue := b[placeholder]
			if aValue == "*" && bValue != "*" {
				b[placeholder] = "*"
				changed = true
			}
			if bValue == "*" && aValue != "*" {
				a[placeholder] = "*"
				changed = true
			}
			if aValue != "*" && bValue != "*" && aValue != bValue {
				break
			}
		}
		if !changed {
			return nil, false
		}
		if reflect.DeepEqual(a, b) {
			return []PermPlaceholders{a}, true
		}
		return []PermPlaceholders{a, b}, true
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

	out := make([]string, 0, len(result))

	for _, r := range result {
		permission := r.Permission

		if len(r.Placeholders) > 0 {
			nodes := make([]string, len(permission.Nodes))
			copy(nodes, permission.Nodes)

			for i, node := range nodes {
				if !isPlaceholderNode(node) {
					continue
				}

				name := node[1 : len(node)-1]
				if v, ok := r.Placeholders[name]; ok {
					nodes[i] = v
				}
			}

			permission.Nodes = nodes
		}

		s := permission.String()
		out = append(out, s)
	}

	sort.Strings(out)
	return out
}
