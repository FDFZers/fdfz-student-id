package cfg

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// SchoolIPMatcher 是校园网 IP 匹配规则的只读快照，支持精确 IP 与 CIDR 网段。
// 规则在配置加载时解析并排序，之后只读，可被并发查询。
//
// 匹配优先级：精确 IP 优先于网段；同一 IP 命中多个网段时取前缀最长者。
type SchoolIPMatcher struct {
	exact    map[netip.Addr]string
	prefixes []schoolIPPrefix
}

// schoolIPPrefix 是一条 CIDR 网段规则，text 是返回给前端直接展示的文本。
type schoolIPPrefix struct {
	prefix netip.Prefix
	text   string
}

// parseSchoolIPMatcher 把 SCHOOL_IPS 的 JSON 键解析为匹配器。
// 键可以是精确 IP（如 202.120.234.145）或 CIDR 网段（如 202.120.234.0/24），
// 值为前端展示文本；网段中的主机位会被掩掉，无法解析、重复或为空的规则会导致启动失败。
func parseSchoolIPMatcher(rules map[string]string) (SchoolIPMatcher, error) {
	matcher := SchoolIPMatcher{
		exact:    make(map[netip.Addr]string, len(rules)),
		prefixes: make([]schoolIPPrefix, 0, len(rules)),
	}
	seenPrefixes := make(map[netip.Prefix]struct{}, len(rules))

	for raw, value := range rules {
		rule := strings.TrimSpace(raw)
		if rule == "" {
			return SchoolIPMatcher{}, fmt.Errorf("empty IP rule")
		}

		text := strings.TrimSpace(value)
		if text == "" {
			return SchoolIPMatcher{}, fmt.Errorf("empty text for IP rule %q", raw)
		}

		if strings.Contains(rule, "/") {
			prefix, err := netip.ParsePrefix(rule)
			if err != nil {
				return SchoolIPMatcher{}, fmt.Errorf("invalid IP range %q: %w", raw, err)
			}
			prefix = normalizeSchoolIPPrefix(prefix)
			if _, ok := seenPrefixes[prefix]; ok {
				return SchoolIPMatcher{}, fmt.Errorf("duplicate IP range %q", raw)
			}
			seenPrefixes[prefix] = struct{}{}
			matcher.prefixes = append(matcher.prefixes, schoolIPPrefix{
				prefix: prefix,
				text:   text,
			})
			continue
		}

		addr, err := netip.ParseAddr(rule)
		if err != nil {
			return SchoolIPMatcher{}, fmt.Errorf("invalid IP %q: %w", raw, err)
		}
		addr = normalizeSchoolIPAddr(addr)
		if _, ok := matcher.exact[addr]; ok {
			return SchoolIPMatcher{}, fmt.Errorf("duplicate IP %q", raw)
		}
		matcher.exact[addr] = text
	}

	// 同一地址可能落入多个网段，按前缀长度从长到短匹配，取最具体的规则。
	sort.Slice(matcher.prefixes, func(i, j int) bool {
		return matcher.prefixes[i].prefix.Bits() > matcher.prefixes[j].prefix.Bits()
	})
	return matcher, nil
}

// normalizeSchoolIPAddr 统一 IP 表示：去掉 IPv6 zone，并把 IPv4-mapped IPv6 还原为 IPv4。
func normalizeSchoolIPAddr(addr netip.Addr) netip.Addr {
	return addr.Unmap().WithZone("")
}

// normalizeSchoolIPPrefix 掩掉 CIDR 的主机位，并把 IPv4-mapped IPv6 网段还原为 IPv4 网段。
func normalizeSchoolIPPrefix(prefix netip.Prefix) netip.Prefix {
	prefix = prefix.Masked()
	if prefix.Addr().Is4In6() {
		if bits := prefix.Bits() - 96; bits >= 0 {
			return netip.PrefixFrom(prefix.Addr().Unmap(), bits)
		}
	}
	return prefix
}

// Lookup 返回 IP 对应的前端展示文本；未命中或 IP 非法时返回 false。
// 精确 IP 优先于网段，网段之间取前缀最长者。
func (m *SchoolIPMatcher) Lookup(ip string) (string, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return "", false
	}
	addr = normalizeSchoolIPAddr(addr)

	if text, ok := m.exact[addr]; ok {
		return text, true
	}
	for _, rule := range m.prefixes {
		if rule.prefix.Contains(addr) {
			return rule.text, true
		}
	}
	return "", false
}
