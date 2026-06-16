package forwardproxy

import (
	"bytes"
	"context"
	"io"
	"net/http"
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
		repl.Set("http.auth.user.id", "testuser")
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
		repl.Set("http.auth.user.id", "invalid:attacker")
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
		repl.Set("http.auth.user.id", strings.Repeat("x", 300))
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
