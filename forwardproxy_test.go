package forwardproxy

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	caddy "github.com/caddyserver/caddy/v2"
)

func TestExtractUsername(t *testing.T) {
	h := &Handler{}

	t.Run("no auth credentials", func(t *testing.T) {
		r, _ := http.NewRequest("GET", "/", nil)
		repl := caddy.NewReplacer()
		ctx := r.Context()
		ctx = context.WithValue(ctx, caddy.ReplacerCtxKey, repl)
		r = r.WithContext(ctx)

		got := h.extractUsername(r)
		if got != "" {
			t.Errorf("expected empty, got %q", got)
		}
	})

	t.Run("valid username from replacer", func(t *testing.T) {
		h.AuthCredentials = [][]byte{[]byte("dGVzdDpwYXNz")}
		r, _ := http.NewRequest("GET", "/", nil)
		repl := caddy.NewReplacer()
		repl.Set(replacerFieldUserID, "testuser")
		ctx := r.Context()
		ctx = context.WithValue(ctx, caddy.ReplacerCtxKey, repl)
		r = r.WithContext(ctx)

		got := h.extractUsername(r)
		if got != "testuser" {
			t.Errorf("expected 'testuser', got %q", got)
		}
	})

	t.Run("invalid prefix rejected", func(t *testing.T) {
		h.AuthCredentials = [][]byte{[]byte("dGVzdDpwYXNz")}
		r, _ := http.NewRequest("GET", "/", nil)
		repl := caddy.NewReplacer()
		repl.Set(replacerFieldUserID, "invalid:attacker")
		ctx := r.Context()
		ctx = context.WithValue(ctx, caddy.ReplacerCtxKey, repl)
		r = r.WithContext(ctx)

		got := h.extractUsername(r)
		if got != "" {
			t.Errorf("expected empty for invalid prefix, got %q", got)
		}
	})

	t.Run("username too long rejected", func(t *testing.T) {
		h.AuthCredentials = [][]byte{[]byte("dGVzdDpwYXNz")}
		r, _ := http.NewRequest("GET", "/", nil)
		repl := caddy.NewReplacer()
		repl.Set(replacerFieldUserID, strings.Repeat("x", 300))
		ctx := r.Context()
		ctx = context.WithValue(ctx, caddy.ReplacerCtxKey, repl)
		r = r.WithContext(ctx)

		got := h.extractUsername(r)
		if got != "" {
			t.Errorf("expected empty for long username, got length %d", len(got))
		}
	})

	t.Run("missing replacer in context", func(t *testing.T) {
		h.AuthCredentials = [][]byte{[]byte("dGVzdDpwYXNz")}
		r, _ := http.NewRequest("GET", "/", nil)

		got := h.extractUsername(r)
		if got != "" {
			t.Errorf("expected empty without replacer, got %q", got)
		}
	})
}

func TestCountingReadCloser(t *testing.T) {
	resetTraffic()

	t.Run("counts rx bytes", func(t *testing.T) {
		body := io.NopCloser(bytes.NewReader([]byte("hello world")))
		crc := &countingReadCloser{rc: body, username: "testuser", isRx: true}

		buf := make([]byte, 32)
		n, err := crc.Read(buf)
		if err != nil && err != io.EOF {
			t.Fatalf("unexpected error: %v", err)
		}
		if n != 11 {
			t.Errorf("expected 11 bytes read, got %d", n)
		}
		crc.Close()

		snap := GetSnapshot()
		u, ok := snap.Users["testuser"]
		if !ok {
			t.Fatal("testuser not found in traffic after counting read")
		}
		if u.RxBytes != 11 {
			t.Errorf("expected 11 rx bytes, got %d", u.RxBytes)
		}
		if u.TxBytes != 0 {
			t.Errorf("expected 0 tx bytes, got %d", u.TxBytes)
		}
	})

	t.Run("counts tx bytes when isRx=false", func(t *testing.T) {
		resetTraffic()

		body := io.NopCloser(bytes.NewReader([]byte("data")))
		crc := &countingReadCloser{rc: body, username: "txuser", isRx: false}

		buf := make([]byte, 32)
		crc.Read(buf)
		crc.Close()

		snap := GetSnapshot()
		u := snap.Users["txuser"]
		if u.RxBytes != 0 {
			t.Errorf("expected 0 rx, got %d", u.RxBytes)
		}
		if u.TxBytes != 4 {
			t.Errorf("expected 4 tx bytes, got %d", u.TxBytes)
		}
	})

	t.Run("multiple reads accumulate", func(t *testing.T) {
		resetTraffic()

		body := io.NopCloser(bytes.NewReader([]byte("abcdefghij")))
		crc := &countingReadCloser{rc: body, username: "multi", isRx: true}

		buf := make([]byte, 3)
		total := 0
		for {
			n, err := crc.Read(buf)
			total += n
			if err == io.EOF || n == 0 {
				break
			}
		}
		crc.Close()

		snap := GetSnapshot()
		u := snap.Users["multi"]
		if u.RxBytes != uint64(total) {
			t.Errorf("rx=%d, expected %d", u.RxBytes, total)
		}
	})

	t.Run("empty body zero traffic", func(t *testing.T) {
		resetTraffic()

		body := io.NopCloser(bytes.NewReader([]byte{}))
		crc := &countingReadCloser{rc: body, username: "empty", isRx: true}

		buf := make([]byte, 32)
		crc.Read(buf)
		crc.Close()

		snap := GetSnapshot()
		if _, ok := snap.Users["empty"]; ok {
			t.Error("empty body should not create user entry")
		}
	})
}

func TestIsLocalhost(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{"localhost", true},
		{"127.0.0.1", true},
		{"::1", true},
		{"example.com", false},
		{"192.168.1.1", false},
		{"", false},
	}
	for _, tt := range tests {
		got := isLocalhost(tt.host)
		if got != tt.want {
			t.Errorf("isLocalhost(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
}

func TestPortIsAllowed(t *testing.T) {
	t.Run("empty allowed ports allows all", func(t *testing.T) {
		h := &Handler{}
		if !h.portIsAllowed("80") {
			t.Error("empty AllowedPorts should allow port 80")
		}
		if !h.portIsAllowed("443") {
			t.Error("empty AllowedPorts should allow port 443")
		}
	})

	t.Run("restricted ports", func(t *testing.T) {
		h := &Handler{AllowedPorts: []int{80, 443}}
		if !h.portIsAllowed("80") {
			t.Error("should allow port 80")
		}
		if !h.portIsAllowed("443") {
			t.Error("should allow port 443")
		}
		if h.portIsAllowed("22") {
			t.Error("should deny port 22")
		}
	})

	t.Run("invalid port strings", func(t *testing.T) {
		h := &Handler{}
		if h.portIsAllowed("not-a-number") {
			t.Error("should reject non-numeric")
		}
		if h.portIsAllowed("-1") {
			t.Error("should reject negative")
		}
		if h.portIsAllowed("0") {
			t.Error("should reject port 0")
		}
		if h.portIsAllowed("99999") {
			t.Error("should reject port > 65535")
		}
	})
}

func TestRemoveHopByHop(t *testing.T) {
	t.Run("removes hop-by-hop headers", func(t *testing.T) {
		h := http.Header{
			"Keep-Alive":          {"timeout=5"},
			"Proxy-Authorization": {"Basic xyz"},
			"Content-Type":        {"text/html"},
			"Connection":          {"keep-alive"},
		}
		removeHopByHop(h)

		if h.Get("Keep-Alive") != "" {
			t.Error("Keep-Alive should be removed")
		}
		if h.Get(headerProxyAuthorization) != "" {
			t.Error(headerProxyAuthorization + " should be removed")
		}
		if h.Get("Content-Type") != "text/html" {
			t.Error("Content-Type should be preserved")
		}
	})

	t.Run("removes Connection-listed headers", func(t *testing.T) {
		h := http.Header{
			"X-Custom":   {"value"},
			"Connection": {"X-Custom, X-Another"},
			"X-Another":  {"to-remove"},
		}
		removeHopByHop(h)

		if h.Get("X-Custom") != "" {
			t.Error("X-Custom should be removed via Connection header")
		}
		if h.Get("X-Another") != "" {
			t.Error("X-Another should be removed via Connection header")
		}
	})
}

func TestShouldServePACFile(t *testing.T) {
	h := &Handler{PACPath: "/proxy.pac"}

	t.Run("matches PAC path", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/proxy.pac", nil)
		if !h.shouldServePACFile(r) {
			t.Error("should serve PAC file for matching path")
		}
	})

	t.Run("does not match other paths", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/other", nil)
		if h.shouldServePACFile(r) {
			t.Error("should not serve PAC file for other path")
		}
	})

	t.Run("no PAC path configured", func(t *testing.T) {
		h2 := &Handler{}
		r := httptest.NewRequest("GET", "/proxy.pac", nil)
		if h2.shouldServePACFile(r) {
			t.Error("should not serve PAC when no path configured")
		}
	})
}

func TestServePacFile(t *testing.T) {
	h := &Handler{}
	r := httptest.NewRequest("GET", "/proxy.pac", nil)
	r.Host = "example.com"
	w := httptest.NewRecorder()

	err := h.servePacFile(w, r)
	if err != nil {
		t.Fatalf("servePacFile error: %v", err)
	}

	body := w.Body.String()
	if body == "" {
		t.Error("PAC file body should not be empty")
	}
	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestServeHiddenPage(t *testing.T) {
	t.Run("auth ok", func(t *testing.T) {
		w := httptest.NewRecorder()
		err := serveHiddenPage(w, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(w.Body.String(), "successfully authenticated") {
			t.Error("should show success message")
		}
	})

	t.Run("auth fail", func(t *testing.T) {
		w := httptest.NewRecorder()
		err := serveHiddenPage(w, http.ErrServerClosed)
		if err == nil {
			t.Fatal("expected error for auth failure")
		}
		if w.Header().Get(headerProxyAuthenticate) == "" {
			t.Error("should set " + headerProxyAuthenticate + " header")
		}
		if w.Code != http.StatusProxyAuthRequired {
			t.Errorf("expected 407, got %d", w.Code)
		}
	})
}

func TestHostIsAllowed(t *testing.T) {
	buildHandler := func(rules []ACLRule) *Handler {
		h := &Handler{ACL: rules}
		for _, rule := range rules {
			for _, subj := range rule.Subjects {
				ar, _ := newACLRule(subj, rule.Allow)
				h.aclRules = append(h.aclRules, ar)
			}
		}
		// default deny rules
		for _, ipDeny := range []string{"10.0.0.0/8", "127.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fe80::/10"} {
			ar, _ := newACLRule(ipDeny, false)
			h.aclRules = append(h.aclRules, ar)
		}
		h.aclRules = append(h.aclRules, &aclAllRule{allow: false})
		return h
	}

	t.Run("allows github.com IP", func(t *testing.T) {
		h := buildHandler([]ACLRule{
			{Subjects: []string{"github.com"}, Allow: true},
		})
		allowed := h.hostIsAllowed("github.com", net.ParseIP("140.82.121.3"))
		if !allowed {
			t.Error("github.com should be allowed")
		}
	})

	t.Run("denies private IP", func(t *testing.T) {
		h := buildHandler(nil)
		allowed := h.hostIsAllowed("local", net.ParseIP("192.168.1.1"))
		if allowed {
			t.Error("192.168.1.1 should be denied")
		}
	})

	t.Run("default deny all", func(t *testing.T) {
		h := buildHandler(nil)
		allowed := h.hostIsAllowed("unknown.com", net.ParseIP("8.8.8.8"))
		if allowed {
			t.Error("should default deny when no allow rule matches")
		}
	})
}

