package forwardproxy

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ACLRule describes an ACL rule.
type ACLRule struct {
	Subjects []string `json:"subjects,omitempty"`
	Allow    bool     `json:"allow,omitempty"`
	Proto    string   `json:"proto,omitempty"`
	Port     string   `json:"port,omitempty"`
	GeoIP    string   `json:"geoip,omitempty"`
	Geosite  string   `json:"geosite,omitempty"`
}

type aclDecision uint8

const (
	aclDecisionAllow = iota
	aclDecisionDeny
	aclDecisionNoMatch
)

type aclMatcher interface {
	tryMatch(ip net.IP, domain string) aclDecision
	tryMatchFull(ip net.IP, domain string, proto string, port int) aclDecision
}

// defaultTryMatchFull provides the default implementation for tryMatchFull.
// It ignores proto/port and delegates to tryMatch.
func defaultTryMatchFull(m aclMatcher, ip net.IP, domain string, proto string, port int) aclDecision {
	return m.tryMatch(ip, domain)
}

type aclIPRule struct {
	net   net.IPNet
	allow bool
}

func (a *aclIPRule) tryMatch(ip net.IP, domain string) aclDecision {
	if !a.net.Contains(ip) {
		return aclDecisionNoMatch
	}
	if a.allow {
		return aclDecisionAllow
	}
	return aclDecisionDeny
}

func (a *aclIPRule) tryMatchFull(ip net.IP, domain string, proto string, port int) aclDecision {
	return defaultTryMatchFull(a, ip, domain, proto, port)
}

type aclDomainRule struct {
	domain            string
	subdomainsAllowed bool
	allow             bool
}

func (a *aclDomainRule) tryMatch(ip net.IP, domain string) aclDecision {
	domain = strings.TrimPrefix(domain, ".")

	if domain == a.domain ||
		a.subdomainsAllowed && strings.HasSuffix(domain, "."+a.domain) {
		if a.allow {
			return aclDecisionAllow
		}
		return aclDecisionDeny
	}
	return aclDecisionNoMatch
}

func (a *aclDomainRule) tryMatchFull(ip net.IP, domain string, proto string, port int) aclDecision {
	return defaultTryMatchFull(a, ip, domain, proto, port)
}

type aclAllRule struct {
	allow bool
}

func (a *aclAllRule) tryMatch(ip net.IP, domain string) aclDecision {
	if a.allow {
		return aclDecisionAllow
	}
	return aclDecisionDeny
}

func (a *aclAllRule) tryMatchFull(ip net.IP, domain string, proto string, port int) aclDecision {
	return defaultTryMatchFull(a, ip, domain, proto, port)
}

// protoPortMatch checks if the given proto and port match the rule's proto/port constraints.
// Returns true if the rule matches (or if no constraints are set).
func protoPortMatch(ruleProto string, rulePort string, proto string, port int) bool {
	if ruleProto != "" && ruleProto != "any" {
		if ruleProto != proto {
			return false
		}
	}
	if rulePort != "" {
		if !portMatches(rulePort, port) {
			return false
		}
	}
	return true
}

// portMatches checks if a port matches a port specification (e.g., "80", "443", "80-443").
func portMatches(spec string, port int) bool {
	if strings.Contains(spec, "-") {
		parts := strings.SplitN(spec, "-", 2)
		lo, err1 := strconv.Atoi(parts[0])
		hi, err2 := strconv.Atoi(parts[1])
		if err1 != nil || err2 != nil {
			return false
		}
		return port >= lo && port <= hi
	}
	p, err := strconv.Atoi(spec)
	if err != nil {
		return false
	}
	return p == port
}

// aclProtoPortRule wraps a base matcher with proto/port filtering.
type aclProtoPortRule struct {
	base      aclMatcher
	proto     string
	port      string
	allow     bool
}

func (a *aclProtoPortRule) tryMatch(ip net.IP, domain string) aclDecision {
	return a.tryMatchFull(ip, domain, "", 0)
}

func (a *aclProtoPortRule) tryMatchFull(ip net.IP, domain string, proto string, port int) aclDecision {
	// If proto/port constraints are set, check them first
	if a.proto != "" || a.port != "" {
		if !protoPortMatch(a.proto, a.port, proto, port) {
			return aclDecisionNoMatch
		}
	}
	// Delegate to base matcher
	return a.base.tryMatch(ip, domain)
}

func newACLRule(ruleSubject string, allow bool) (aclMatcher, error) {
	return newACLRuleWithProtoPort(ruleSubject, allow, "", "")
}

func newACLRuleWithProtoPort(ruleSubject string, allow bool, proto, port string) (aclMatcher, error) {
	if ruleSubject == "all" {
		if proto == "" && port == "" {
			return &aclAllRule{allow: allow}, nil
		}
		return &aclProtoPortRule{
			base:  &aclAllRule{allow: allow},
			proto: proto,
			port:  port,
			allow: allow,
		}, nil
	}
	_, ipNet, err := net.ParseCIDR(ruleSubject)
	if err != nil {
		ip := net.ParseIP(ruleSubject)
		// support specifying just an IP
		if ip.To4() != nil {
			_, ipNet, err = net.ParseCIDR(ruleSubject + "/32")
		} else if ip.To16() != nil {
			_, ipNet, err = net.ParseCIDR(ruleSubject + "/128")
		}
	}
	if err == nil {
		base := &aclIPRule{net: *ipNet, allow: allow}
		if proto == "" && port == "" {
			return base, nil
		}
		return &aclProtoPortRule{
			base:  base,
			proto: proto,
			port:  port,
			allow: allow,
		}, nil
	}

	subdomainsAllowed := false
	if strings.HasPrefix(ruleSubject, `*.`) {
		subdomainsAllowed = true
		ruleSubject = ruleSubject[2:]
	}
	err = isValidDomainLite(ruleSubject)
	if err != nil {
		return nil, errors.New(ruleSubject + " could not be parsed as either IP, IP network, or domain: " + err.Error())
	}
	base := &aclDomainRule{domain: ruleSubject, subdomainsAllowed: subdomainsAllowed, allow: allow}
	if proto == "" && port == "" {
		return base, nil
	}
	return &aclProtoPortRule{
		base:  base,
		proto: proto,
		port:  port,
		allow: allow,
	}, nil
}

// parseProtoPort parses a proto/port prefix from an ACL subject.
// Returns the cleaned subject, proto, port, and any error.
// Examples: "tcp/80" → ("all", "tcp", "80", nil), "udp/53" → ("all", "udp", "53", nil)
// "example.com" → ("example.com", "", "", nil)
func parseProtoPort(subject string) (cleanedSubject, proto, port string, err error) {
	parts := strings.SplitN(subject, "/", 2)
	if len(parts) == 2 {
		proto = strings.ToLower(parts[0])
		port = parts[1]
		if proto != "tcp" && proto != "udp" && proto != "any" {
			return "", "", "", fmt.Errorf("unsupported protocol %q (expected tcp, udp, or any)", proto)
		}
		// Validate port
		if strings.Contains(port, "-") {
			rangeParts := strings.SplitN(port, "-", 2)
			lo, err1 := strconv.Atoi(rangeParts[0])
			hi, err2 := strconv.Atoi(rangeParts[1])
			if err1 != nil || err2 != nil || lo < 1 || hi > 65535 || lo > hi {
				return "", "", "", fmt.Errorf("invalid port range %q", port)
			}
		} else {
			p, err3 := strconv.Atoi(port)
			if err3 != nil || p < 1 || p > 65535 {
				return "", "", "", fmt.Errorf("invalid port %q", port)
			}
		}
		return "all", proto, port, nil
	}
	return subject, "", "", nil
}

// aclGeoIPRule matches IPs by country using a geoIPReader.
type aclGeoIPRule struct {
	country  string
	allow    bool
	reader   *geoIPReader
	negated  bool // true if country starts with "!" (match non-country IPs)
}

func (a *aclGeoIPRule) tryMatch(ip net.IP, domain string) aclDecision {
	if ip == nil {
		return aclDecisionNoMatch
	}
	if a.reader == nil {
		return aclDecisionNoMatch
	}
	country := a.reader.lookupCountry(ip)
	matched := false
	if a.negated {
		matched = country != a.country
	} else {
		matched = country == a.country
	}
	if matched {
		if a.allow {
			return aclDecisionAllow
		}
		return aclDecisionDeny
	}
	return aclDecisionNoMatch
}

func (a *aclGeoIPRule) tryMatchFull(ip net.IP, domain string, proto string, port int) aclDecision {
	return defaultTryMatchFull(a, ip, domain, proto, port)
}

// aclGeositeRule matches domains by category using a geositeReader.
type aclGeositeRule struct {
	category string
	allow    bool
	reader   *geositeReader
	negated  bool // true if category starts with "!"
}

func (a *aclGeositeRule) tryMatch(ip net.IP, domain string) aclDecision {
	if domain == "" {
		return aclDecisionNoMatch
	}
	if a.reader == nil {
		return aclDecisionNoMatch
	}
	hasCategory := a.reader.hasCategory(domain, a.category)
	matched := false
	if a.negated {
		matched = !hasCategory
	} else {
		matched = hasCategory
	}
	if matched {
		if a.allow {
			return aclDecisionAllow
		}
		return aclDecisionDeny
	}
	return aclDecisionNoMatch
}

func (a *aclGeositeRule) tryMatchFull(ip net.IP, domain string, proto string, port int) aclDecision {
	return defaultTryMatchFull(a, ip, domain, proto, port)
}

// isValidDomainLite shamelessly rejects non-LDH names. returns nil if domains seems valid
func isValidDomainLite(domain string) error {
	for i := 0; i < len(domain); i++ {
		c := domain[i]
		if 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || c == '_' || '0' <= c && c <= '9' ||
			c == '-' || c == '.' {
			continue
		}
		return errors.New("character " + string(c) + " is not allowed")
	}
	sections := strings.Split(domain, ".")
	for _, s := range sections {
		if len(s) == 0 {
			return errors.New("empty section between dots in domain name or trailing dot")
		}
		if len(s) > 63 {
			return errors.New("domain name section is too long")
		}
	}
	return nil
}
