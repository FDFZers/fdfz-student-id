package cfg

import (
	"testing"
)

func TestSchoolIPMatcherLookup(t *testing.T) {
	const fdfzText = "复旦大学附属中学"
	const ffxhText = "复旦附中徐汇分校"
	const ffqpText = "复旦附中青浦分校"
	const ffpdText = "复旦附中浦东分校"
	const ffjaText = "复旦附中静安分校"

	matcher, err := parseSchoolIPMatcher(map[string]string{
		"202.120.234.145":       fdfzText,
		"202.120.235.99/24":     fdfzText, // 主机位在加载时被掩掉
		"10.0.0.0/8":            ffxhText,
		"10.1.2.0/24":           ffqpText,
		"2001:db8::/32":         ffpdText,
		"192.168.1.1":           ffjaText,
		"::ffff:172.16.0.0/108": ffpdText, // IPv4-mapped IPv6 网段
		"::ffff:202.120.236.1":  ffxhText, // IPv4-mapped IPv6 精确地址
		" 203.0.113.10 ":        ffqpText, // 键与值两侧空白会被忽略
	})
	if err != nil {
		t.Fatalf("parseSchoolIPMatcher() error = %v", err)
	}

	tests := []struct {
		name   string
		ip     string
		want   string
		wantOK bool
	}{
		{"exact IPv4", "202.120.234.145", fdfzText, true},
		{"exact IPv4 misses neighbor", "202.120.234.146", "", false},
		{"CIDR IPv4", "10.2.3.4", ffxhText, true},
		{"longest prefix wins", "10.1.2.3", ffqpText, true},
		{"CIDR with masked host bits", "202.120.235.42", fdfzText, true},
		{"IPv6 CIDR", "2001:db8::1", ffpdText, true},
		{"IPv6 CIDR misses", "2001:db9::1", "", false},
		{"IPv6 zone is ignored", "2001:db8::1%eth0", ffpdText, true},
		{"exact IPv4 mapped IPv6", "::ffff:202.120.236.1", ffxhText, true},
		{"IPv4 mapped IPv6 CIDR", "172.16.5.5", ffpdText, true},
		{"trimmed rule", "203.0.113.10", ffqpText, true},
		{"invalid IP", "not-an-ip", "", false},
		{"empty IP", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := matcher.Lookup(tt.ip)
			if ok != tt.wantOK || got != tt.want {
				t.Errorf("Lookup(%q) = (%q, %v), want (%q, %v)", tt.ip, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func TestParseSchoolIPMatcherRejectsInvalidRules(t *testing.T) {
	tests := []struct {
		name  string
		rules map[string]string
	}{
		{"invalid IP", map[string]string{"not-an-ip": "复旦大学附属中学"}},
		{"invalid CIDR", map[string]string{"10.0.0.0/33": "复旦大学附属中学"}},
		{"empty rule", map[string]string{"": "复旦大学附属中学"}},
		{"blank rule", map[string]string{"   ": "复旦大学附属中学"}},
		{"empty text", map[string]string{"202.120.234.145": ""}},
		{"blank text", map[string]string{"202.120.234.145": "   "}},
		{"duplicate CIDR after masking", map[string]string{
			"10.0.0.0/8": "复旦大学附属中学",
			"10.1.2.3/8": "复旦附中徐汇分校",
		}},
		{"duplicate exact after unmapping", map[string]string{
			"202.120.234.145":        "复旦大学附属中学",
			"::ffff:202.120.234.145": "复旦附中徐汇分校",
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseSchoolIPMatcher(tt.rules); err == nil {
				t.Errorf("parseSchoolIPMatcher(%v) error = nil, want error", tt.rules)
			}
		})
	}
}

func TestEmptySchoolIPMatcher(t *testing.T) {
	var matcher SchoolIPMatcher
	if text, ok := matcher.Lookup("202.120.234.145"); ok || text != "" {
		t.Errorf("zero-value matcher Lookup() = (%q, %v), want (\"\", false)", text, ok)
	}
}
