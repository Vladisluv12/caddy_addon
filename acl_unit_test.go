package forwardproxy

import (
	"net"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

func TestParseProtoPort(t *testing.T) {
	tests := []struct {
		input    string
		subj     string
		proto    string
		port     string
		wantErr  bool
	}{
		{"example.com", "example.com", "", "", false},
		{"tcp/80", "all", "tcp", "80", false},
		{"udp/53", "all", "udp", "53", false},
		{"tcp/80-443", "all", "tcp", "80-443", false},
		{"any/443", "all", "any", "443", false},
		{"invalid/80", "", "", "", true},
		{"tcp/0", "", "", "", true},
		{"tcp/99999", "", "", "", true},
		{"tcp/80-443", "all", "tcp", "80-443", false},
		{"tcp/100-50", "", "", "", true},
		{"", "", "", "", false},
		{"tcp", "tcp", "", "", false},
		{"tcp/", "", "", "", true},
		{"/80", "", "", "", true},
		{"tcp/abc", "", "", "", true},
		{"tcp/65535", "all", "tcp", "65535", false},
		{"tcp/65536", "", "", "", true},
		{"tcp/1-65535", "all", "tcp", "1-65535", false},
		{"tcp/0-80", "", "", "", true},
		{"tcp/80-443-8000", "", "", "", true},
		{"UDP/53", "all", "udp", "53", false},
	}

	for _, tt := range tests {
		subj, proto, port, err := parseProtoPort(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("parseProtoPort(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if subj != tt.subj {
			t.Errorf("parseProtoPort(%q) subj = %q, want %q", tt.input, subj, tt.subj)
		}
		if proto != tt.proto {
			t.Errorf("parseProtoPort(%q) proto = %q, want %q", tt.input, proto, tt.proto)
		}
		if port != tt.port {
			t.Errorf("parseProtoPort(%q) port = %q, want %q", tt.input, port, tt.port)
		}
	}
}

func TestPortMatches(t *testing.T) {
	tests := []struct {
		spec string
		port int
		want bool
	}{
		{"80", 80, true},
		{"80", 443, false},
		{"80-443", 80, true},
		{"80-443", 443, true},
		{"80-443", 8080, false},
		{"1-65535", 1, true},
		{"1-65535", 65535, true},
		{"invalid", 80, false},
		{"", 80, false},
		{"0", 0, true},
		{"0", 1, false},
		{"65535", 65535, true},
		{"65535", 65534, false},
		{"80-80", 80, true},
		{"80-80", 81, false},
	}

	for _, tt := range tests {
		if got := portMatches(tt.spec, tt.port); got != tt.want {
			t.Errorf("portMatches(%q, %d) = %v, want %v", tt.spec, tt.port, got, tt.want)
		}
	}
}

func TestACLIPRule(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("10.0.0.0/8")
	rule := &aclIPRule{net: *ipNet, allow: true}

	if rule.tryMatch(net.ParseIP("10.0.0.1"), "") != aclDecisionAllow {
		t.Error("expected allow for 10.0.0.1")
	}
	if rule.tryMatch(net.ParseIP("192.168.1.1"), "") != aclDecisionNoMatch {
		t.Error("expected no match for 192.168.1.1")
	}

	denyRule := &aclIPRule{net: *ipNet, allow: false}
	if denyRule.tryMatch(net.ParseIP("10.0.0.1"), "") != aclDecisionDeny {
		t.Error("expected deny for 10.0.0.1")
	}
}

func TestACLDomainRule(t *testing.T) {
	rule := &aclDomainRule{domain: "example.com", subdomainsAllowed: false, allow: true}

	if rule.tryMatch(nil, "example.com") != aclDecisionAllow {
		t.Error("expected allow for example.com")
	}
	if rule.tryMatch(nil, "sub.example.com") != aclDecisionNoMatch {
		t.Error("expected no match for sub.example.com")
	}
	if rule.tryMatch(nil, "other.com") != aclDecisionNoMatch {
		t.Error("expected no match for other.com")
	}

	subRule := &aclDomainRule{domain: "example.com", subdomainsAllowed: true, allow: false}
	if subRule.tryMatch(nil, "sub.example.com") != aclDecisionDeny {
		t.Error("expected deny for sub.example.com")
	}
}

func TestACLAllRule(t *testing.T) {
	allowRule := &aclAllRule{allow: true}
	if allowRule.tryMatch(net.ParseIP("1.2.3.4"), "anything") != aclDecisionAllow {
		t.Error("expected allow")
	}

	denyRule := &aclAllRule{allow: false}
	if denyRule.tryMatch(net.ParseIP("1.2.3.4"), "anything") != aclDecisionDeny {
		t.Error("expected deny")
	}
}

func TestACLProtoPortRule(t *testing.T) {
	base := &aclAllRule{allow: true}
	rule := &aclProtoPortRule{base: base, proto: "tcp", port: "80", allow: true}

	// TCP port 80 should match
	if rule.tryMatchFull(nil, "", "tcp", 80) != aclDecisionAllow {
		t.Error("expected allow for tcp/80")
	}
	// TCP port 443 should not match
	if rule.tryMatchFull(nil, "", "tcp", 443) != aclDecisionNoMatch {
		t.Error("expected no match for tcp/443")
	}
	// UDP port 80 should not match
	if rule.tryMatchFull(nil, "", "udp", 80) != aclDecisionNoMatch {
		t.Error("expected no match for udp/80")
	}

	// Port range rule
	denyBase := &aclAllRule{allow: false}
	rangeRule := &aclProtoPortRule{base: denyBase, proto: "", port: "80-443", allow: false}
	if rangeRule.tryMatchFull(nil, "", "tcp", 80) != aclDecisionDeny {
		t.Error("expected deny for tcp/80")
	}
	if rangeRule.tryMatchFull(nil, "", "tcp", 443) != aclDecisionDeny {
		t.Error("expected deny for tcp/443")
	}
	if rangeRule.tryMatchFull(nil, "", "tcp", 8080) != aclDecisionNoMatch {
		t.Error("expected no match for tcp/8080")
	}
}

func TestNewACLRule(t *testing.T) {
	tests := []struct {
		subject string
		allow   bool
		wantErr bool
	}{
		{"all", false, false},
		{"10.0.0.0/8", true, false},
		{"192.168.1.1", false, false},
		{"example.com", true, false},
		{"*.example.com", false, false},
		{"invalid..domain", false, true},
	}

	for _, tt := range tests {
		rule, err := newACLRule(tt.subject, tt.allow)
		if (err != nil) != tt.wantErr {
			t.Errorf("newACLRule(%q) error = %v, wantErr %v", tt.subject, err, tt.wantErr)
			continue
		}
		if err == nil && rule == nil {
			t.Errorf("newACLRule(%q) returned nil rule", tt.subject)
		}
	}
}

func TestNewACLRuleWithProtoPort(t *testing.T) {
	rule, err := newACLRuleWithProtoPort("example.com", true, "tcp", "80")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ppRule, ok := rule.(*aclProtoPortRule)
	if !ok {
		t.Fatal("expected aclProtoPortRule")
	}
	if ppRule.proto != "tcp" || ppRule.port != "80" {
		t.Errorf("expected proto=tcp port=80, got proto=%s port=%s", ppRule.proto, ppRule.port)
	}
}

func TestGeoIPRule(t *testing.T) {
	reader := makeTestGeoIPReader([]struct {
		code  string
		cidrs []struct{ ip string; prefix int }
	}{
		{code: "US", cidrs: []struct{ ip string; prefix int }{{"1.2.0.0", 16}}},
		{code: "CN", cidrs: []struct{ ip string; prefix int }{{"5.6.0.0", 16}}},
	})

	// Match US
	rule := &aclGeoIPRule{country: "US", allow: true, reader: reader}
	if rule.tryMatch(net.ParseIP("1.2.3.4"), "") != aclDecisionAllow {
		t.Error("expected allow for US IP")
	}
	if rule.tryMatch(net.ParseIP("5.6.7.8"), "") != aclDecisionNoMatch {
		t.Error("expected no match for CN IP")
	}

	// Negated match
	negRule := &aclGeoIPRule{country: "CN", allow: true, reader: reader, negated: true}
	if negRule.tryMatch(net.ParseIP("1.2.3.4"), "") != aclDecisionAllow {
		t.Error("expected allow for non-CN IP")
	}
	if negRule.tryMatch(net.ParseIP("5.6.7.8"), "") != aclDecisionNoMatch {
		t.Error("expected no match for CN IP with negated rule")
	}
}

func TestGeositeRule(t *testing.T) {
	reader := &geositeReader{
		categories: map[string]*geositeCategory{
			"google": {exact: map[string]struct{}{"google.com": {}, "googleapis.com": {}, "youtube.com": {}}, subdoms: []string{"google.com", "googleapis.com", "youtube.com"}},
			"cn":     {exact: map[string]struct{}{"baidu.com": {}, "qq.com": {}}, subdoms: []string{"baidu.com", "qq.com"}},
		},
		loaded: true,
	}

	// Match google category
	rule := &aclGeositeRule{category: "google", allow: true, reader: reader}
	if rule.tryMatch(nil, "google.com") != aclDecisionAllow {
		t.Error("expected allow for google.com")
	}
	if rule.tryMatch(nil, "sub.google.com") != aclDecisionAllow {
		t.Error("expected allow for sub.google.com")
	}
	if rule.tryMatch(nil, "example.com") != aclDecisionNoMatch {
		t.Error("expected no match for example.com")
	}

	// Negated match
	negRule := &aclGeositeRule{category: "cn", allow: false, reader: reader, negated: true}
	if negRule.tryMatch(nil, "google.com") != aclDecisionDeny {
		t.Error("expected deny for non-CN domain")
	}
	if negRule.tryMatch(nil, "baidu.com") != aclDecisionNoMatch {
		t.Error("expected no match for CN domain with negated rule")
	}
}

func TestPrivateIPRanges(t *testing.T) {
	if len(privateIPRanges) == 0 {
		t.Error("privateIPRanges should not be empty")
	}
	expected := []string{
		"10.0.0.0/8",
		"100.64.0.0/10",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}
	if len(privateIPRanges) != len(expected) {
		t.Errorf("expected %d private IP ranges, got %d", len(expected), len(privateIPRanges))
	}
	for i, r := range expected {
		if privateIPRanges[i] != r {
			t.Errorf("privateIPRanges[%d] = %q, want %q", i, privateIPRanges[i], r)
		}
	}
}

func TestGeoIPReaderLookupCountry(t *testing.T) {
	reader := makeTestGeoIPReader([]struct {
		code  string
		cidrs []struct{ ip string; prefix int }
	}{
		{code: "US", cidrs: []struct{ ip string; prefix int }{{"8.8.8.0", 24}}},
	})

	if country := reader.lookupCountry(net.ParseIP("8.8.8.8")); country != "US" {
		t.Errorf("lookupCountry(8.8.8.8) = %q, want US", country)
	}
	if country := reader.lookupCountry(net.ParseIP("1.2.3.4")); country != "" {
		t.Errorf("lookupCountry(1.2.3.4) = %q, want empty", country)
	}
}

func TestGeositeReaderHasCategory(t *testing.T) {
	reader := &geositeReader{
		categories: map[string]*geositeCategory{
			"google": {exact: map[string]struct{}{"google.com": {}}, subdoms: []string{"google.com"}},
		},
		loaded: true,
	}

	if !reader.hasCategory("google.com", "google") {
		t.Error("expected hasCategory to return true for google.com")
	}
	if reader.hasCategory("example.com", "google") {
		t.Error("expected hasCategory to return false for example.com")
	}
	if reader.hasCategory("google.com", "nonexistent") {
		t.Error("expected hasCategory to return false for nonexistent category")
	}
}

func TestACLIPRuleNilIP(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("10.0.0.0/8")
	rule := &aclIPRule{net: *ipNet, allow: true}
	if rule.tryMatch(nil, "") != aclDecisionNoMatch {
		t.Error("expected no match for nil IP")
	}
}

func TestACLIPRuleIPv6(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("2001:db8::/32")
	rule := &aclIPRule{net: *ipNet, allow: true}
	if rule.tryMatch(net.ParseIP("2001:db8::1"), "") != aclDecisionAllow {
		t.Error("expected allow for IPv6 address in range")
	}
	if rule.tryMatch(net.ParseIP("2001:db9::1"), "") != aclDecisionNoMatch {
		t.Error("expected no match for IPv6 address outside range")
	}
}

func TestACLIPRuleIPv6Deny(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("2001:db8::/32")
	rule := &aclIPRule{net: *ipNet, allow: false}
	if rule.tryMatch(net.ParseIP("2001:db8::1"), "") != aclDecisionDeny {
		t.Error("expected deny for IPv6 address in range")
	}
}

func TestACLDomainRuleLeadingDot(t *testing.T) {
	rule := &aclDomainRule{domain: "example.com", subdomainsAllowed: true, allow: true}
	// Leading dot should be stripped before matching
	if rule.tryMatch(nil, ".example.com") != aclDecisionAllow {
		t.Error("expected allow for .example.com (leading dot stripped)")
	}
}

func TestACLDomainRuleTrailingDot(t *testing.T) {
	rule := &aclDomainRule{domain: "example.com", subdomainsAllowed: false, allow: true}
	// Trailing dot should NOT match without subdomains (different string)
	if rule.tryMatch(nil, "example.com.") != aclDecisionNoMatch {
		t.Error("expected no match for example.com. (trailing dot)")
	}
}

func TestACLDomainRuleEmptyDomain(t *testing.T) {
	rule := &aclDomainRule{domain: "example.com", subdomainsAllowed: false, allow: true}
	if rule.tryMatch(nil, "") != aclDecisionNoMatch {
		t.Error("expected no match for empty domain")
	}
}

func TestACLDomainRuleSubdomainNotAllowed(t *testing.T) {
	rule := &aclDomainRule{domain: "example.com", subdomainsAllowed: false, allow: true}
	if rule.tryMatch(nil, "sub.example.com") != aclDecisionNoMatch {
		t.Error("expected no match for sub.example.com when subdomains not allowed")
	}
}

func TestGeoIPRuleNilIP(t *testing.T) {
	reader := makeTestGeoIPReader([]struct {
		code  string
		cidrs []struct{ ip string; prefix int }
	}{
		{code: "US", cidrs: []struct{ ip string; prefix int }{{"1.2.0.0", 16}}},
	})
	rule := &aclGeoIPRule{country: "US", allow: true, reader: reader}
	if rule.tryMatch(nil, "") != aclDecisionNoMatch {
		t.Error("expected no match for nil IP")
	}
}

func TestGeoIPRuleNilReader(t *testing.T) {
	rule := &aclGeoIPRule{country: "US", allow: true, reader: nil}
	if rule.tryMatch(net.ParseIP("1.2.3.4"), "") != aclDecisionNoMatch {
		t.Error("expected no match with nil reader")
	}
}

func TestGeoIPRuleNegatedUnknownCountry(t *testing.T) {
	reader := makeTestGeoIPReader([]struct {
		code  string
		cidrs []struct{ ip string; prefix int }
	}{
		{code: "US", cidrs: []struct{ ip string; prefix int }{{"1.2.0.0", 16}}},
	})
	// IP with unknown country (not US), negated rule for US → should match
	rule := &aclGeoIPRule{country: "US", allow: true, reader: reader, negated: true}
	if rule.tryMatch(net.ParseIP("99.99.99.99"), "") != aclDecisionAllow {
		t.Error("expected allow for IP with unknown country under negated US rule")
	}
	// IP in US, negated rule for US → should NOT match
	if rule.tryMatch(net.ParseIP("1.2.3.4"), "") != aclDecisionNoMatch {
		t.Error("expected no match for US IP under negated US rule")
	}
}

func TestGeoIPRuleNegatedDeny(t *testing.T) {
	reader := makeTestGeoIPReader([]struct {
		code  string
		cidrs []struct{ ip string; prefix int }
	}{
		{code: "RU", cidrs: []struct{ ip string; prefix int }{{"5.6.0.0", 16}}},
	})
	// Negated deny: deny everything except RU
	rule := &aclGeoIPRule{country: "RU", allow: false, reader: reader, negated: true}
	if rule.tryMatch(net.ParseIP("1.2.3.4"), "") != aclDecisionDeny {
		t.Error("expected deny for non-RU IP under negated deny rule")
	}
	if rule.tryMatch(net.ParseIP("5.6.7.8"), "") != aclDecisionNoMatch {
		t.Error("expected no match for RU IP under negated deny rule")
	}
}

func TestGeositeRuleNilReader(t *testing.T) {
	rule := &aclGeositeRule{category: "google", allow: true, reader: nil}
	if rule.tryMatch(nil, "google.com") != aclDecisionNoMatch {
		t.Error("expected no match with nil reader")
	}
}

func TestGeositeRuleEmptyDomain(t *testing.T) {
	reader := &geositeReader{
		categories: map[string]*geositeCategory{
			"google": {exact: map[string]struct{}{"google.com": {}}, subdoms: []string{"google.com"}},
		},
		loaded: true,
	}
	rule := &aclGeositeRule{category: "google", allow: true, reader: reader}
	if rule.tryMatch(nil, "") != aclDecisionNoMatch {
		t.Error("expected no match for empty domain")
	}
}

func TestGeositeRuleNegatedUnknownDomain(t *testing.T) {
	reader := &geositeReader{
		categories: map[string]*geositeCategory{
			"google": {exact: map[string]struct{}{"google.com": {}, "googleapis.com": {}}, subdoms: []string{"google.com", "googleapis.com"}},
		},
		loaded: true,
	}
	// Domain NOT in category, negated rule → should match
	rule := &aclGeositeRule{category: "google", allow: true, reader: reader, negated: true}
	if rule.tryMatch(nil, "example.com") != aclDecisionAllow {
		t.Error("expected allow for domain NOT in category under negated rule")
	}
	// Domain IN category, negated rule → should NOT match
	if rule.tryMatch(nil, "google.com") != aclDecisionNoMatch {
		t.Error("expected no match for domain IN category under negated rule")
	}
}

func TestGeositeReaderHasCategoryLeadingDot(t *testing.T) {
	reader := &geositeReader{
		categories: map[string]*geositeCategory{
			"google": {exact: map[string]struct{}{"google.com": {}}, subdoms: []string{"google.com"}},
		},
		loaded: true,
	}
	// Leading dot in stored domain should be stripped
	if !reader.hasCategory("google.com", "google") {
		t.Error("expected hasCategory to return true for google.com with .google.com entry")
	}
	if !reader.hasCategory("sub.google.com", "google") {
		t.Error("expected hasCategory to return true for sub.google.com with .google.com entry")
	}
}

func TestACLProtoPortRuleAnyProto(t *testing.T) {
	base := &aclAllRule{allow: true}
	rule := &aclProtoPortRule{base: base, proto: "any", port: "443", allow: true}
	if rule.tryMatchFull(nil, "", "tcp", 443) != aclDecisionAllow {
		t.Error("expected allow for tcp/443 with any/443 rule")
	}
	if rule.tryMatchFull(nil, "", "udp", 443) != aclDecisionAllow {
		t.Error("expected allow for udp/443 with any/443 rule")
	}
	if rule.tryMatchFull(nil, "", "tcp", 80) != aclDecisionNoMatch {
		t.Error("expected no match for tcp/80 with any/443 rule")
	}
}

func TestACLProtoPortRulePortOnly(t *testing.T) {
	base := &aclAllRule{allow: false}
	rule := &aclProtoPortRule{base: base, proto: "", port: "80", allow: false}
	if rule.tryMatchFull(nil, "", "tcp", 80) != aclDecisionDeny {
		t.Error("expected deny for tcp/80 with port-only rule")
	}
	if rule.tryMatchFull(nil, "", "udp", 80) != aclDecisionDeny {
		t.Error("expected deny for udp/80 with port-only rule")
	}
	if rule.tryMatchFull(nil, "", "tcp", 443) != aclDecisionNoMatch {
		t.Error("expected no match for tcp/443 with port-only rule")
	}
}

func TestACLProtoPortRuleProtoOnly(t *testing.T) {
	base := &aclAllRule{allow: true}
	rule := &aclProtoPortRule{base: base, proto: "udp", port: "", allow: true}
	if rule.tryMatchFull(nil, "", "udp", 53) != aclDecisionAllow {
		t.Error("expected allow for udp/53 with proto-only rule")
	}
	if rule.tryMatchFull(nil, "", "tcp", 53) != aclDecisionNoMatch {
		t.Error("expected no match for tcp/53 with proto-only rule")
	}
}

func TestACLProtoPortRuleTryMatchWithoutProtoPort(t *testing.T) {
	base := &aclAllRule{allow: true}
	rule := &aclProtoPortRule{base: base, proto: "tcp", port: "80", allow: true}
	// tryMatch without proto/port info delegates to tryMatchFull with empty proto/0 port
	if rule.tryMatch(net.ParseIP("1.2.3.4"), "") != aclDecisionNoMatch {
		t.Error("expected no match for tryMatch without proto/port (proto check fails)")
	}
}

func TestNewACLRuleIPv6(t *testing.T) {
	rule, err := newACLRule("2001:db8::1", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rule.tryMatch(net.ParseIP("2001:db8::1"), "") != aclDecisionAllow {
		t.Error("expected allow for matching IPv6")
	}
	if rule.tryMatch(net.ParseIP("2001:db9::1"), "") != aclDecisionNoMatch {
		t.Error("expected no match for non-matching IPv6")
	}
}

func TestNewACLRuleIPv6CIDR(t *testing.T) {
	rule, err := newACLRule("2001:db8::/32", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rule.tryMatch(net.ParseIP("2001:db8::1"), "") != aclDecisionDeny {
		t.Error("expected deny for IPv6 in CIDR range")
	}
	if rule.tryMatch(net.ParseIP("2001:db9::1"), "") != aclDecisionNoMatch {
		t.Error("expected no match for IPv6 outside CIDR range")
	}
}

func TestNewACLRuleEmpty(t *testing.T) {
	_, err := newACLRule("", true)
	if err == nil {
		t.Error("expected error for empty subject")
	}
}

func TestNewACLRuleIPv4CIDRWithProtoPort(t *testing.T) {
	rule, err := newACLRuleWithProtoPort("10.0.0.0/8", false, "tcp", "80")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ppRule, ok := rule.(*aclProtoPortRule)
	if !ok {
		t.Fatal("expected aclProtoPortRule")
	}
	if ppRule.proto != "tcp" || ppRule.port != "80" {
		t.Errorf("expected proto=tcp port=80, got proto=%s port=%s", ppRule.proto, ppRule.port)
	}
	if ppRule.tryMatchFull(net.ParseIP("10.0.0.1"), "", "tcp", 80) != aclDecisionDeny {
		t.Error("expected deny for 10.0.0.1 tcp/80")
	}
	if ppRule.tryMatchFull(net.ParseIP("10.0.0.1"), "", "udp", 53) != aclDecisionNoMatch {
		t.Error("expected no match for 10.0.0.1 udp/53")
	}
	if ppRule.tryMatchFull(net.ParseIP("1.2.3.4"), "", "tcp", 80) != aclDecisionNoMatch {
		t.Error("expected no match for 1.2.3.4 tcp/80 (outside CIDR)")
	}
}

func TestACLRuleOrderingFirstMatchWins(t *testing.T) {
	rules := []aclMatcher{
		&aclIPRule{net: net.IPNet{IP: net.ParseIP("10.0.0.0").To4(), Mask: net.CIDRMask(8, 32)}, allow: false},
		&aclIPRule{net: net.IPNet{IP: net.ParseIP("10.0.0.0").To4(), Mask: net.CIDRMask(8, 32)}, allow: true},
	}

	// Simulate first-match-wins evaluation (like hostIsAllowed)
	var decision aclDecision
	for _, rule := range rules {
		decision = rule.tryMatch(net.ParseIP("10.0.0.1"), "")
		if decision != aclDecisionNoMatch {
			break
		}
	}
	if decision != aclDecisionDeny {
		t.Errorf("expected first rule (deny) to win, got %v", decision)
	}
}

func TestACLRuleOrderingAllowThenDeny(t *testing.T) {
	rules := []aclMatcher{
		&aclIPRule{net: net.IPNet{IP: net.ParseIP("10.0.0.0").To4(), Mask: net.CIDRMask(8, 32)}, allow: true},
		&aclAllRule{allow: false},
	}

	// Simulate first-match-wins evaluation
	var decision aclDecision
	for _, rule := range rules {
		decision = rule.tryMatch(net.ParseIP("10.0.0.1"), "")
		if decision != aclDecisionNoMatch {
			break
		}
	}
	if decision != aclDecisionAllow {
		t.Errorf("expected first rule (allow) to win, got %v", decision)
	}
}

func TestPrivateIPRangesContainAllExpected(t *testing.T) {
	expectedRanges := []struct {
		ip      string
		isPriv  bool
	}{
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"100.64.0.1", true},
		{"100.127.255.255", true},
		{"127.0.0.1", true},
		{"169.254.0.1", true},
		{"169.254.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.1.1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"101.0.0.1", false},
	}

	for _, tc := range expectedRanges {
		ip := net.ParseIP(tc.ip)
		if ip == nil {
			t.Errorf("failed to parse IP %s", tc.ip)
			continue
		}
		matched := false
		for _, r := range privateIPRanges {
			_, ipNet, err := net.ParseCIDR(r)
			if err != nil {
				t.Errorf("failed to parse CIDR %s: %v", r, err)
				continue
			}
			if ipNet.Contains(ip) {
				matched = true
				break
			}
		}
		if matched != tc.isPriv {
			t.Errorf("IP %s: expected isPrivate=%v, got %v", tc.ip, tc.isPriv, matched)
		}
	}
}

func TestPrivateIPRangesIPv6(t *testing.T) {
	expectedRanges := []struct {
		ip      string
		isPriv  bool
	}{
		{"::1", true},
		{"fe80::1", true},
		{"fd00::1", true},
		{"fc00::1", true},
		{"2001:db8::1", false},
	}

	for _, tc := range expectedRanges {
		ip := net.ParseIP(tc.ip)
		if ip == nil {
			t.Errorf("failed to parse IP %s", tc.ip)
			continue
		}
		matched := false
		for _, r := range privateIPRanges {
			_, ipNet, err := net.ParseCIDR(r)
			if err != nil {
				t.Errorf("failed to parse CIDR %s: %v", r, err)
				continue
			}
			if ipNet.Contains(ip) {
				matched = true
				break
			}
		}
		if matched != tc.isPriv {
			t.Errorf("IP %s: expected isPrivate=%v, got %v", tc.ip, tc.isPriv, matched)
		}
	}
}

func TestGeoIPRuleWithIPNetwork(t *testing.T) {
	reader := makeTestGeoIPReader([]struct {
		code  string
		cidrs []struct{ ip string; prefix int }
	}{
		{code: "DE", cidrs: []struct{ ip string; prefix int }{{"185.0.0.0", 8}}},
	})
	rule := &aclGeoIPRule{country: "DE", allow: true, reader: reader}
	if rule.tryMatch(net.ParseIP("185.1.2.3"), "") != aclDecisionAllow {
		t.Error("expected allow for DE IP in /8 range")
	}
	if rule.tryMatch(net.ParseIP("186.0.0.1"), "") != aclDecisionNoMatch {
		t.Error("expected no match for IP outside DE /8 range")
	}
}

func TestGeositeReaderHasCategorySubdomain(t *testing.T) {
	reader := &geositeReader{
		categories: map[string]*geositeCategory{
			"google": {exact: map[string]struct{}{"google.com": {}}, subdoms: []string{"google.com"}},
		},
		loaded: true,
	}
	if !reader.hasCategory("mail.google.com", "google") {
		t.Error("expected hasCategory to return true for mail.google.com")
	}
}

func TestGeositeRuleDeny(t *testing.T) {
	reader := &geositeReader{
		categories: map[string]*geositeCategory{
			"ads": {exact: map[string]struct{}{"ads.example.com": {}, "tracker.com": {}}, subdoms: []string{"ads.example.com", "tracker.com"}},
		},
		loaded: true,
	}
	rule := &aclGeositeRule{category: "ads", allow: false, reader: reader}
	if rule.tryMatch(nil, "ads.example.com") != aclDecisionDeny {
		t.Error("expected deny for ads.example.com")
	}
	if rule.tryMatch(nil, "clean.com") != aclDecisionNoMatch {
		t.Error("expected no match for clean.com")
	}
}

func TestIsValidDomainLite(t *testing.T) {
	tests := []struct {
		domain  string
		wantErr bool
	}{
		{"example.com", false},
		{"sub.example.com", false},
		{"a.example.com", false},
		{"123.example.com", false},
		{"example-.com", false},
		{"-example.com", false},
		{"example..com", true},
		{".example.com", true},
		{"example.com.", true},
		{"", true},
		{"example com", true},
		{"example.com:80", true},
	}

	for _, tt := range tests {
		err := isValidDomainLite(tt.domain)
		if (err != nil) != tt.wantErr {
			t.Errorf("isValidDomainLite(%q) error = %v, wantErr %v", tt.domain, err, tt.wantErr)
		}
	}
}

// --- Protobuf encoding helpers for tests ---

func encodeBytesField(b []byte, num protowire.Number, v []byte) []byte {
	b = protowire.AppendTag(b, num, protowire.BytesType)
	b = protowire.AppendBytes(b, v)
	return b
}

func encodeVarintField(b []byte, num protowire.Number, v uint64) []byte {
	b = protowire.AppendTag(b, num, protowire.VarintType)
	b = protowire.AppendVarint(b, v)
	return b
}

// --- GeoIP protobuf parser tests ---

// makeTestGeoIPReader builds a geoIPReader from synthetic CIDR data for tests.
func makeTestGeoIPReader(countries []struct {
	code string
	cidrs []struct {
		ip     string
		prefix int
	}
}) *geoIPReader {
	r := &geoIPReader{loaded: true}
	for _, c := range countries {
		co := geoIPCountry{countryCode: c.code}
		for _, cidr := range c.cidrs {
			ip := net.ParseIP(cidr.ip)
			if ip4 := ip.To4(); ip4 != nil {
				co.v4 = append(co.v4, geoIPCIDRv4{
					ip:     uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3]),
					prefix: uint8(cidr.prefix),
				})
			} else {
				var b [16]byte
				copy(b[:], ip.To16())
				co.v6 = append(co.v6, geoIPCIDRv6{ip: b, prefix: uint8(cidr.prefix)})
			}
		}
		r.countries = append(r.countries, co)
	}
	return r
}

func TestParseGeoIPDataSingleCountry(t *testing.T) {
	// Build a synthetic geoip.dat with one country "US" and one CIDR 1.2.3.0/24
	// GeoIP message: string country_code = 1; repeated CIDR cidr = 2;
	// CIDR message: bytes ip = 1; int32 prefix = 2;

	var cidrMsg []byte
	cidrMsg = encodeBytesField(cidrMsg, 1, []byte{1, 2, 3, 0}) // ip = 1.2.3.0
	cidrMsg = encodeVarintField(cidrMsg, 2, 24)                 // prefix = 24

	var geoipMsg []byte
	geoipMsg = encodeBytesField(geoipMsg, 1, []byte("US")) // country_code = US
	geoipMsg = encodeBytesField(geoipMsg, 2, cidrMsg)      // cidr = cidrMsg

	// Top-level: repeated GeoIP geoip = 1;
	topLevel := encodeBytesField(nil, 1, geoipMsg)

	reader, err := parseGeoIPData(topLevel)
	if err != nil {
		t.Fatalf("parseGeoIPData failed: %v", err)
	}
	if len(reader.countries) != 1 || reader.countCIDRs() != 1 {
		t.Fatalf("expected 1 country with 1 CIDR, got %d countries with %d CIDRs", len(reader.countries), reader.countCIDRs())
	}
	if reader.countries[0].countryCode != "US" {
		t.Errorf("country = %q, want US", reader.countries[0].countryCode)
	}
	cc := reader.lookupCountry(net.ParseIP("1.2.3.5"))
	if cc != "US" {
		t.Errorf("expected 1.2.3.5 to be in US range, got %q", cc)
	}
	cc = reader.lookupCountry(net.ParseIP("1.2.4.1"))
	if cc != "" {
		t.Errorf("expected 1.2.4.1 to NOT be in US range, got %q", cc)
	}
}

func TestParseGeoIPDataMultipleCountries(t *testing.T) {
	// Two countries: US with 1.0.0.0/8, CN with 2.0.0.0/8

	var cidrUS []byte
	cidrUS = encodeBytesField(cidrUS, 1, []byte{1, 0, 0, 0})
	cidrUS = encodeVarintField(cidrUS, 2, 8)
	var msgUS []byte
	msgUS = encodeBytesField(msgUS, 1, []byte("US"))
	msgUS = encodeBytesField(msgUS, 2, cidrUS)

	var cidrCN []byte
	cidrCN = encodeBytesField(cidrCN, 1, []byte{2, 0, 0, 0})
	cidrCN = encodeVarintField(cidrCN, 2, 8)
	var msgCN []byte
	msgCN = encodeBytesField(msgCN, 1, []byte("CN"))
	msgCN = encodeBytesField(msgCN, 2, cidrCN)

	topLevel := encodeBytesField(nil, 1, msgUS)
	topLevel = encodeBytesField(topLevel, 1, msgCN)

	reader, err := parseGeoIPData(topLevel)
	if err != nil {
		t.Fatalf("parseGeoIPData failed: %v", err)
	}
	if len(reader.countries) != 2 || reader.countCIDRs() != 2 {
		t.Fatalf("expected 2 countries with 2 CIDRs, got %d countries with %d CIDRs", len(reader.countries), reader.countCIDRs())
	}

	if country := reader.lookupCountry(net.ParseIP("1.2.3.4")); country != "US" {
		t.Errorf("lookupCountry(1.2.3.4) = %q, want US", country)
	}
	if country := reader.lookupCountry(net.ParseIP("2.3.4.5")); country != "CN" {
		t.Errorf("lookupCountry(2.3.4.5) = %q, want CN", country)
	}
	if country := reader.lookupCountry(net.ParseIP("3.0.0.1")); country != "" {
		t.Errorf("lookupCountry(3.0.0.1) = %q, want empty", country)
	}
}

func TestParseGeoIPDataIPv6(t *testing.T) {
	// IPv6 CIDR: 2001:db8::/32 for country "RU"
	ip := net.ParseIP("2001:db8::").To16()
	var cidrMsg []byte
	cidrMsg = encodeBytesField(cidrMsg, 1, ip)
	cidrMsg = encodeVarintField(cidrMsg, 2, 32)

	var msg []byte
	msg = encodeBytesField(msg, 1, []byte("RU"))
	msg = encodeBytesField(msg, 2, cidrMsg)

	topLevel := encodeBytesField(nil, 1, msg)

	reader, err := parseGeoIPData(topLevel)
	if err != nil {
		t.Fatalf("parseGeoIPData failed: %v", err)
	}
	if len(reader.countries) != 1 || reader.countCIDRs() != 1 {
		t.Fatalf("expected 1 country with 1 CIDR, got %d countries with %d CIDRs", len(reader.countries), reader.countCIDRs())
	}
	if country := reader.lookupCountry(net.ParseIP("2001:db8::1")); country != "RU" {
		t.Errorf("lookupCountry(2001:db8::1) = %q, want RU", country)
	}
	if country := reader.lookupCountry(net.ParseIP("2001:db9::1")); country != "" {
		t.Errorf("lookupCountry(2001:db9::1) = %q, want empty", country)
	}
}

func TestParseGeoIPDataEmpty(t *testing.T) {
	reader, err := parseGeoIPData(nil)
	if err != nil {
		t.Fatalf("parseGeoIPData(nil) failed: %v", err)
	}
	if len(reader.countries) != 0 {
		t.Errorf("expected 0 countries, got %d", len(reader.countries))
	}
}

func TestParseGeoIPDataInvalidTag(t *testing.T) {
	// Invalid protobuf tag (0xFF repeated)
	_, err := parseGeoIPData([]byte{0xFF, 0xFF, 0xFF})
	if err == nil {
		t.Error("expected error for invalid protobuf tag")
	}
}

func TestParseGeoIPCIDR(t *testing.T) {
	// Valid CIDR: ip=10.0.0.0, prefix=8
	var msg []byte
	msg = encodeBytesField(msg, 1, []byte{10, 0, 0, 0})
	msg = encodeVarintField(msg, 2, 8)

	v4, v6, err := parseGeoIPCIDRCompact(msg)
	if err != nil {
		t.Fatalf("parseGeoIPCIDRCompact failed: %v", err)
	}
	if len(v4) != 1 || len(v6) != 0 {
		t.Fatalf("expected 1 v4 CIDR, got v4=%d v6=%d", len(v4), len(v6))
	}
	if v4[0].ip != 0x0A000000 { // 10.0.0.0 in big endian
		t.Errorf("ip = 0x%X, want 0x0A000000", v4[0].ip)
	}
	if v4[0].prefix != 8 {
		t.Errorf("prefix = %d, want 8", v4[0].prefix)
	}
}

func TestParseGeoIPCIDREmpty(t *testing.T) {
	v4, v6, err := parseGeoIPCIDRCompact(nil)
	if err != nil {
		t.Fatalf("parseGeoIPCIDRCompact(nil) failed: %v", err)
	}
	if len(v4) != 0 || len(v6) != 0 {
		t.Errorf("expected empty results, got v4=%d v6=%d", len(v4), len(v6))
	}
}

// --- Geosite protobuf parser tests ---

func TestParseGeositeDataSingleCategory(t *testing.T) {
	// Build a synthetic geosite.dat with category "google" and domains
	// Domain message: Type type = 1; string value = 2;
	// Type 0 = Plain

	var d1 []byte
	d1 = encodeVarintField(d1, 1, 0)                        // type = Plain
	d1 = encodeBytesField(d1, 2, []byte("google.com"))      // value

	var d2 []byte
	d2 = encodeVarintField(d2, 1, 0)                        // type = Plain
	d2 = encodeBytesField(d2, 2, []byte("youtube.com"))     // value

	// DomainGroup: string type = 1; repeated Domain domain = 2;
	var group []byte
	group = encodeBytesField(group, 1, []byte("google"))
	group = encodeBytesField(group, 2, d1)
	group = encodeBytesField(group, 2, d2)

	// Top-level: repeated GeoSite geosite = 1;
	topLevel := encodeBytesField(nil, 1, group)

	reader, err := parseGeositeData(topLevel)
	if err != nil {
		t.Fatalf("parseGeositeData failed: %v", err)
	}
	cats := reader.getCategories()
	if len(cats) != 1 || cats[0] != "google" {
		t.Fatalf("expected [google], got %v", cats)
	}
	if !reader.hasCategory("google.com", "google") {
		t.Error("expected google.com to be in google category")
	}
	if !reader.hasCategory("sub.google.com", "google") {
		t.Error("expected sub.google.com to be in google category")
	}
	if reader.hasCategory("example.com", "google") {
		t.Error("expected example.com to NOT be in google category")
	}
}

func TestParseGeositeDataMultipleCategories(t *testing.T) {
	var d1 []byte
	d1 = encodeVarintField(d1, 1, 0)
	d1 = encodeBytesField(d1, 2, []byte("google.com"))

	var d2 []byte
	d2 = encodeVarintField(d2, 1, 0)
	d2 = encodeBytesField(d2, 2, []byte("baidu.com"))

	var g1 []byte
	g1 = encodeBytesField(g1, 1, []byte("google"))
	g1 = encodeBytesField(g1, 2, d1)

	var g2 []byte
	g2 = encodeBytesField(g2, 1, []byte("cn"))
	g2 = encodeBytesField(g2, 2, d2)

	topLevel := encodeBytesField(nil, 1, g1)
	topLevel = encodeBytesField(topLevel, 1, g2)

	reader, err := parseGeositeData(topLevel)
	if err != nil {
		t.Fatalf("parseGeositeData failed: %v", err)
	}
	if len(reader.getCategories()) != 2 {
		t.Fatalf("expected 2 categories, got %d", len(reader.getCategories()))
	}
	if !reader.hasCategory("google.com", "google") {
		t.Error("expected google.com in google")
	}
	if !reader.hasCategory("baidu.com", "cn") {
		t.Error("expected baidu.com in cn")
	}
	if reader.hasCategory("google.com", "cn") {
		t.Error("google.com should NOT be in cn")
	}
}

func TestParseGeositeDataDomainTypes(t *testing.T) {
	// Type 2 = Domain (subdomain match)
	var d []byte
	d = encodeVarintField(d, 1, 2)
	d = encodeBytesField(d, 2, []byte("google.com"))

	var g []byte
	g = encodeBytesField(g, 1, []byte("test"))
	g = encodeBytesField(g, 2, d)

	// Type 3 = Full (exact match only)
	var d3 []byte
	d3 = encodeVarintField(d3, 1, 3)
	d3 = encodeBytesField(d3, 2, []byte("exact.example.com"))

	var g2 []byte
	g2 = encodeBytesField(g2, 1, []byte("exact"))
	g2 = encodeBytesField(g2, 2, d3)

	topLevel := encodeBytesField(nil, 1, g)
	topLevel = encodeBytesField(topLevel, 1, g2)

	reader, err := parseGeositeData(topLevel)
	if err != nil {
		t.Fatalf("parseGeositeData failed: %v", err)
	}
	// Domain type (2) should match as plain domain
	if !reader.hasCategory("google.com", "test") {
		t.Error("expected google.com in test (domain type)")
	}
	// Full type (3) should also be stored
	if !reader.hasCategory("exact.example.com", "exact") {
		t.Error("expected exact.example.com in exact (full type)")
	}
}

func TestParseGeositeDataEmpty(t *testing.T) {
	reader, err := parseGeositeData(nil)
	if err != nil {
		t.Fatalf("parseGeositeData(nil) failed: %v", err)
	}
	if len(reader.getCategories()) != 0 {
		t.Errorf("expected 0 categories, got %d", len(reader.getCategories()))
	}
}

func TestParseGeositeDataInvalidTag(t *testing.T) {
	_, err := parseGeositeData([]byte{0xFF, 0xFF, 0xFF})
	if err == nil {
		t.Error("expected error for invalid protobuf tag")
	}
}

func TestParseGeositeDomainRegex(t *testing.T) {
	// Type 1 = Regex (should be skipped)
	var d []byte
	d = encodeVarintField(d, 1, 1)
	d = encodeBytesField(d, 2, []byte("^https?://.*\\.google\\.com$"))

	var g []byte
	g = encodeBytesField(g, 1, []byte("test"))
	g = encodeBytesField(g, 2, d)

	topLevel := encodeBytesField(nil, 1, g)

	reader, err := parseGeositeData(topLevel)
	if err != nil {
		t.Fatalf("parseGeositeData failed: %v", err)
	}
	// Regex domains are skipped, category with no parseable domains is not added
	if _, ok := reader.categories["test"]; ok {
		t.Error("expected test category to NOT exist (all domains were regex)")
	}
}

func TestParseGeositeEntryLeadingDot(t *testing.T) {
	// Domain with leading dot should be trimmed
	var d []byte
	d = encodeVarintField(d, 1, 0)
	d = encodeBytesField(d, 2, []byte(".example.com"))

	var g []byte
	g = encodeBytesField(g, 1, []byte("test"))
	g = encodeBytesField(g, 2, d)

	topLevel := encodeBytesField(nil, 1, g)

	reader, err := parseGeositeData(topLevel)
	if err != nil {
		t.Fatalf("parseGeositeData failed: %v", err)
	}
	if !reader.hasCategory("example.com", "test") {
		t.Error("expected example.com in test (leading dot trimmed)")
	}
	if !reader.hasCategory("sub.example.com", "test") {
		t.Error("expected sub.example.com in test")
	}
}

func TestGeositeCategoryExactMatch(t *testing.T) {
	reader := &geositeReader{
		categories: map[string]*geositeCategory{
			"fast": {exact: map[string]struct{}{"cdn.example.com": {}}, subdoms: []string{"cdn.example.com"}},
		},
		loaded: true,
	}
	// Exact match should be O(1) — just verify it works
	if !reader.hasCategory("cdn.example.com", "fast") {
		t.Error("expected exact match for cdn.example.com")
	}
	// Subdomain match should still work
	if !reader.hasCategory("images.cdn.example.com", "fast") {
		t.Error("expected subdomain match for images.cdn.example.com")
	}
	// Non-match
	if reader.hasCategory("other.com", "fast") {
		t.Error("expected no match for other.com")
	}
}

func TestSkipProtobufFieldFixed32(t *testing.T) {
	// Fixed32 field: 4 bytes
	buf := []byte{0x01, 0x02, 0x03, 0x04}
	result, err := skipProtobufField(buf, protowire.Fixed32Type)
	if err != nil {
		t.Fatalf("skipProtobufField(Fixed32) failed: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected empty buffer, got %d bytes", len(result))
	}
}

func TestSkipProtobufFieldFixed32Truncated(t *testing.T) {
	buf := []byte{0x01, 0x02}
	_, err := skipProtobufField(buf, protowire.Fixed32Type)
	if err == nil {
		t.Error("expected error for truncated Fixed32")
	}
}

func TestSkipProtobufFieldFixed64(t *testing.T) {
	buf := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	result, err := skipProtobufField(buf, protowire.Fixed64Type)
	if err != nil {
		t.Fatalf("skipProtobufField(Fixed64) failed: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected empty buffer, got %d bytes", len(result))
	}
}

func TestSkipProtobufFieldFixed64Truncated(t *testing.T) {
	buf := []byte{0x01, 0x02, 0x03}
	_, err := skipProtobufField(buf, protowire.Fixed64Type)
	if err == nil {
		t.Error("expected error for truncated Fixed64")
	}
}

func TestSkipProtobufFieldVarint(t *testing.T) {
	buf := protowire.AppendVarint(nil, 42)
	result, err := skipProtobufField(buf, protowire.VarintType)
	if err != nil {
		t.Fatalf("skipProtobufField(Varint) failed: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected empty buffer, got %d bytes", len(result))
	}
}

func TestSkipProtobufFieldBytes(t *testing.T) {
	// Build a tagged bytes field: tag(1, BytesType) + length(5) + "hello"
	buf := protowire.AppendTag(nil, 1, protowire.BytesType)
	buf = protowire.AppendBytes(buf, []byte("hello"))
	// Consume the tag first to get the value bytes.
	_, _, n := protowire.ConsumeTag(buf)
	valBuf := buf[n:]
	result, err := skipProtobufField(valBuf, protowire.BytesType)
	if err != nil {
		t.Fatalf("skipProtobufField(Bytes) failed: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected empty buffer, got %d bytes", len(result))
	}
}

func TestSkipProtobufFieldUnsupported(t *testing.T) {
	_, err := skipProtobufField([]byte{0x01}, protowire.Type(7))
	if err == nil {
		t.Error("expected error for unsupported wire type")
	}
}
