// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Caching is purposefully ignored.

package forwardproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	caddy "github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/forwardproxy/httpclient"
	"go.uber.org/zap"
	"golang.org/x/net/proxy"
)

const (
	headerProxyAuthenticate  = "Proxy-Authenticate"
	headerProxyAuthorization = "Proxy-Authorization"
	replacerFieldUserID      = "http.auth.user.id"
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler implements a forward proxy.
//
// EXPERIMENTAL: This handler is still experimental and subject to breaking changes.
type Handler struct {
	logger *zap.Logger

	// Filename of the PAC file to serve.
	PACPath string `json:"pac_path,omitempty"`

	// If true, the Forwarded header will not be augmented with your IP address.
	HideIP bool `json:"hide_ip,omitempty"`

	// If true, the Via header will not be added.
	HideVia bool `json:"hide_via,omitempty"`

	// If true, the strict check preventing HTTP upstreams will be disabled.
	DisableInsecureUpstreamsCheck bool `json:"disable_insecure_upstreams_check,omitempty"`

	// Host(s) (and ports) of the proxy. When you configure a client,
	// you will give it the host (and port) of the proxy to use.
	Hosts caddyhttp.MatchHost `json:"hosts,omitempty"`

	// Optional probe resistance. (See documentation.)
	ProbeResistance *ProbeResistance `json:"probe_resistance,omitempty"`

	// How long to wait before timing out initial TCP connections.
	DialTimeout caddy.Duration `json:"dial_timeout,omitempty"`

	// Maximum number of idle connections to keep open, globally.
	// Default: 50. Set to -1 for no limit.
	// See https://pkg.go.dev/net/http#Transport.MaxIdleConns
	MaxIdleConns int `json:"max_idle_conns,omitempty"`

	// Maximum number of idle connections to keep open per host.
	// Default: 0, which uses Go's default of 2.
	// See https://pkg.go.dev/net/http#Transport.MaxIdleConnsPerHost
	MaxIdleConnsPerHost int `json:"max_idle_conns_per_host,omitempty"`

	// Optionally configure an upstream proxy to use.
	Upstream string `json:"upstream,omitempty"`

	// Access control list.
	ACL []ACLRule `json:"acl,omitempty"`

	// Ports to be allowed to connect to (if non-empty).
	AllowedPorts []int `json:"allowed_ports,omitempty"`

	// Path to per-user traffic stats file. Default: /etc/rixxx-panel/naive_users.json
	TrafficFile string `json:"traffic_file,omitempty"`

	httpTransport *http.Transport

	// overridden dialContext allows us to redirect requests to upstream proxy
	dialContext func(ctx context.Context, network, address string) (net.Conn, error)
	upstream    *url.URL // address of upstream proxy

	aclRules []aclMatcher

	// AuthCredentials stores base64-encoded "username:password" pairs for Basic auth.
	// Note: Caddy v2 has built-in authentication modules (http.authentication.providers.http_basic)
	// but using them here would require adapting the module to Caddy's authenticator interface.
	// The current hand-rolled approach is simpler but duplicates functionality.
	AuthCredentials [][]byte `json:"auth_credentials,omitempty"` // slice with base64-encoded credentials

	// authHashes maps username → SHA-256 hash of decoded "username:password"
	// Pre-computed during Provision to resist timing attacks during credential comparison.
	authHashes map[string][32]byte `json:"-"`
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.forward_proxy",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision ensures that h is set up properly before use.
func (h *Handler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger(h)

	if h.DialTimeout <= 0 {
		h.DialTimeout = caddy.Duration(30 * time.Second)
	}

	// Default to 50 max idle connections if not specified,
	// or no limit if -1 is specified.
	maxIdleConns := h.MaxIdleConns
	if maxIdleConns == 0 {
		maxIdleConns = 50
	}
	if maxIdleConns < 0 {
		maxIdleConns = 0
	}

	trafficFilePath := h.TrafficFile
	if trafficFilePath == "" {
		trafficFilePath = "/etc/rixxx-panel/naive_users.json"
	}
	InitTraffic(trafficFilePath, h.logger)

	h.authHashes = make(map[string][32]byte)
	for _, cred := range h.AuthCredentials {
		decoded := make([]byte, base64.StdEncoding.DecodedLen(len(cred)))
		n, err := base64.StdEncoding.Decode(decoded, cred)
		if err != nil {
			return fmt.Errorf("failed to decode auth credential: %w", err)
		}
		decoded = decoded[:n]
		i := strings.IndexByte(string(decoded), ':')
		if i < 0 {
			return fmt.Errorf("auth credential has invalid format (missing colon separator)")
		}
		username := string(decoded[:i])
		if _, exists := h.authHashes[username]; exists {
			return fmt.Errorf("duplicate username in auth credentials: %s", username)
		}
		h.authHashes[username] = sha256.Sum256(decoded)
	}

	h.httpTransport = &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		MaxIdleConns:        maxIdleConns,
		MaxIdleConnsPerHost: h.MaxIdleConnsPerHost,
		IdleConnTimeout:     60 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	if err := h.initACLRules(); err != nil {
		return err
	}
	h.aclRules = append(h.aclRules, &aclAllRule{allow: true})

	if err := h.validateProbeResistance(); err != nil {
		return err
	}

	dialer := &net.Dialer{
		Timeout:   time.Duration(h.DialTimeout),
		KeepAlive: 30 * time.Second,
		DualStack: true,
	}
	h.dialContext = dialer.DialContext
	h.httpTransport.DialContext = func(ctx context.Context, network string, address string) (net.Conn, error) {
		return h.dialContextCheckACL(ctx, network, address)
	}

	if h.Upstream != "" {
		if err := h.initUpstreamDialer(dialer); err != nil {
			return err
		}
	}

	return nil
}

func (h *Handler) initACLRules() error {
	for _, rule := range h.ACL {
		for _, subj := range rule.Subjects {
			ar, err := newACLRule(subj, rule.Allow)
			if err != nil {
				return err
			}
			h.aclRules = append(h.aclRules, ar)
		}
	}
	for _, ipDeny := range []string{
		"10.0.0.0/8",
		"127.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"::1/128",
		"fe80::/10",
	} {
		ar, err := newACLRule(ipDeny, false)
		if err != nil {
			return err
		}
		h.aclRules = append(h.aclRules, ar)
	}
	return nil
}

func (h *Handler) validateProbeResistance() error {
	if h.ProbeResistance == nil {
		return nil
	}
	if h.AuthCredentials == nil {
		return fmt.Errorf("probe resistance requires authentication")
	}
	if len(h.ProbeResistance.Domain) > 0 {
		h.logger.Info("Secret domain used to connect to proxy: " + h.ProbeResistance.Domain)
	}
	return nil
}

func (h *Handler) initUpstreamDialer(dialer *net.Dialer) error {
	upstreamURL, err := url.Parse(h.Upstream)
	if err != nil {
		return fmt.Errorf("bad upstream URL: %v", err)
	}
	h.upstream = upstreamURL

	if !h.DisableInsecureUpstreamsCheck && !isLocalhost(h.upstream.Hostname()) && h.upstream.Scheme != "https" {
		return errors.New("insecure schemes are only allowed to localhost upstreams")
	}

	registerHTTPDialer := func(u *url.URL, _ proxy.Dialer) (proxy.Dialer, error) {
		d, err := httpclient.NewHTTPConnectDialer(h.upstream.String())
		if err != nil {
			return nil, err
		}
		d.Dialer = *dialer
		if isLocalhost(h.upstream.Hostname()) && h.upstream.Scheme == "https" {
			h.logger.Info("Localhost upstream detected, disabling verification of TLS certificate")
			h.logger.Warn("TLS certificate verification is disabled for localhost upstream; this is safe only in trusted development environments")
			d.DialTLS = func(network string, address string) (net.Conn, string, error) {
				conn, err := tls.Dial(network, address, &tls.Config{
					InsecureSkipVerify: true, // #nosec G402 — intentionally disabled for localhost self-signed certs
					MinVersion:         tls.VersionTLS12,
				})
				if err != nil {
					return nil, "", err
				}
				return conn, conn.ConnectionState().NegotiatedProtocol, nil
			}
		}
		return d, nil
	}
	proxy.RegisterDialerType("https", registerHTTPDialer)
	proxy.RegisterDialerType("http", registerHTTPDialer)

	upstreamDialer, err := proxy.FromURL(h.upstream, dialer)
	if err != nil {
		return errors.New("failed to create proxy to upstream: " + err.Error())
	}

	if ctxDialer, ok := upstreamDialer.(dialContexter); ok {
		h.dialContext = ctxDialer.DialContext
	} else {
		h.dialContext = func(ctx context.Context, network string, address string) (net.Conn, error) {
			return upstreamDialer.Dial(network, address)
		}
	}
	return nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	reqHost, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		reqHost = r.Host
	}

	if err := h.handleAuthAndRouting(w, r, next, reqHost); err != nil {
		return err
	}

	if r.ProtoMajor != 1 && r.ProtoMajor != 2 && r.ProtoMajor != 3 {
		return caddyhttp.Error(http.StatusHTTPVersionNotSupported,
			fmt.Errorf("unsupported HTTP major version: %d", r.ProtoMajor))
	}

	ctx := context.Background()
	if !h.HideIP {
		ctxHeader := make(http.Header)
		for k, v := range r.Header {
			if kL := strings.ToLower(k); kL == "forwarded" || kL == "x-forwarded-for" {
				ctxHeader[k] = v
			}
		}
		ctxHeader.Add("Forwarded", "for=\""+r.RemoteAddr+"\"")
		ctx = context.WithValue(ctx, httpclient.ContextKeyHeader{}, ctxHeader)
	}

	username := h.extractUsername(r)

	if r.Method == http.MethodConnect {
		return h.handleConnect(w, r, ctx, username)
	}
	return h.handleNonConnect(w, r, ctx, username)
}

// handleAuthAndRouting performs authentication, probe resistance, and PAC file checks.
// Returns nil if the request should continue to be proxied.
func (h *Handler) handleAuthAndRouting(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler, reqHost string) error {
	var authErr error
	if h.AuthCredentials != nil {
		authErr = h.checkCredentials(r)
	}

	if h.ProbeResistance != nil && len(h.ProbeResistance.Domain) > 0 && reqHost == h.ProbeResistance.Domain {
		return serveHiddenPage(w, authErr)
	}

	if h.Hosts.Match(r) && (r.Method != http.MethodConnect || authErr != nil) {
		if h.shouldServePACFile(r) {
			return h.servePacFile(w, r)
		}
		return next.ServeHTTP(w, r)
	}

	if authErr != nil {
		if h.ProbeResistance != nil {
			return next.ServeHTTP(w, r)
		}
		w.Header().Set(headerProxyAuthenticate, "Basic realm=\"Caddy Secure Web Proxy\"")
		return caddyhttp.Error(http.StatusProxyAuthRequired, authErr)
	}
	return nil
}

func (h *Handler) handleConnect(w http.ResponseWriter, r *http.Request, ctx context.Context, username string) error {
	if r.ProtoMajor == 2 || r.ProtoMajor == 3 {
		if len(r.URL.Scheme) > 0 || len(r.URL.Path) > 0 {
			return caddyhttp.Error(http.StatusBadRequest,
				fmt.Errorf("CONNECT request has :scheme and/or :path pseudo-header fields"))
		}
	}

	hostPort := r.URL.Host
	if hostPort == "" {
		hostPort = r.Host
	}

	switch r.ProtoMajor {
	case 1:
		return h.handleConnectH1(w, r, ctx, hostPort, username)
	case 2:
		fallthrough
	case 3:
		return h.handleConnectH2H3(w, r, ctx, hostPort, username)
	}

	panic("There was a check for http version, yet it's incorrect")
}

func (h *Handler) handleConnectH1(w http.ResponseWriter, r *http.Request, ctx context.Context, hostPort, username string) error {
	// Set padding header before writing response
	paddingLen := rand.Intn(32) + 30
	padding := make([]byte, paddingLen)
	bits := rand.Uint64()
	for i := 0; i < 16; i++ {
		padding[i] = "!#$()+<>?@[]^`{}"[bits&15]
		bits >>= 4
	}
	for i := 16; i < paddingLen; i++ {
		padding[i] = '~'
	}
	w.Header().Set("Padding", string(padding))

	w.WriteHeader(http.StatusOK)
	if err := http.NewResponseController(w).Flush(); err != nil {
		return caddyhttp.Error(http.StatusInternalServerError,
			fmt.Errorf("ResponseWriter flush error: %v", err))
	}

	// Hijack immediately after writing 200 OK — before the client
	// sends further tunnel data, to prevent Go's HTTP server from
	// consuming the subsequent bytes.
	clientConn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError,
			fmt.Errorf("hijack failed: %v", err))
	}
	defer clientConn.Close()

	_ = clientConn.SetDeadline(time.Time{})

	if n := brw.Reader.Buffered(); n > 0 {
		rbuf, _ := brw.Peek(n)
		_, _ = clientConn.Write(rbuf) // not needed, but harmless
		_ = rbuf
	}

	targetConn, err := h.dialContextCheckACL(ctx, "tcp", hostPort)
	if err != nil {
		return err
	}
	if targetConn == nil {
		return caddyhttp.Error(http.StatusForbidden,
			fmt.Errorf("hostname %s is not allowed", hostPort))
	}
	defer targetConn.Close()

	if username != "" {
		incConn(username)
		defer decConn(username)
	}

	return dualStream(targetConn, clientConn, clientConn, false, username)
}

func (h *Handler) handleConnectH2H3(w http.ResponseWriter, r *http.Request, ctx context.Context, hostPort, username string) error {
	paddingLen := rand.Intn(32) + 30
	padding := make([]byte, paddingLen)
	bits := rand.Uint64()
	for i := 0; i < 16; i++ {
		padding[i] = "!#$()+<>?@[]^`{}"[bits&15]
		bits >>= 4
	}
	for i := 16; i < paddingLen; i++ {
		padding[i] = '~'
	}
	w.Header().Set("Padding", string(padding))

	w.WriteHeader(http.StatusOK)
	if err := http.NewResponseController(w).Flush(); err != nil {
		return caddyhttp.Error(http.StatusInternalServerError,
			fmt.Errorf("ResponseWriter flush error: %v", err))
	}

	targetConn, err := h.dialContextCheckACL(ctx, "tcp", hostPort)
	if err != nil {
		return err
	}
	if targetConn == nil {
		return caddyhttp.Error(http.StatusForbidden,
			fmt.Errorf("hostname %s is not allowed", hostPort))
	}
	defer targetConn.Close()

	if username != "" {
		incConn(username)
		defer decConn(username)
	}

	defer r.Body.Close()
	return dualStream(targetConn, r.Body, w, r.Header.Get("Padding") != "", username)
}

func (h *Handler) handleNonConnect(w http.ResponseWriter, r *http.Request, ctx context.Context, username string) error {
	h.prepareNonConnectRequest(r)

	response, err := h.doRoundTrip(r, ctx, username)
	if err != nil {
		return err
	}

	if username != "" && response != nil && response.Body != nil {
		response.Body = &countingReadCloser{rc: response.Body, username: username, isRx: true}
	}

	return forwardResponse(w, response)
}

func (h *Handler) prepareNonConnectRequest(r *http.Request) {
	if r.URL.Scheme == "" {
		r.URL.Scheme = "http"
	}
	if r.URL.Host == "" {
		r.URL.Host = r.Host
	}
	r.Proto = "HTTP/1.1"
	r.ProtoMajor = 1
	r.ProtoMinor = 1
	r.RequestURI = ""

	removeHopByHop(r.Header)

	if !h.HideIP {
		r.Header.Add("Forwarded", "for=\""+r.RemoteAddr+"\"")
	}
	if !h.HideVia {
		r.Header.Add("Via", strconv.Itoa(r.ProtoMajor)+"."+strconv.Itoa(r.ProtoMinor)+" caddy")
	}
}

func (h *Handler) doRoundTrip(r *http.Request, ctx context.Context, username string) (*http.Response, error) {
	if h.upstream != nil {
		return h.roundTripUpstream(r, ctx)
	}

	if r.Body != nil && (r.Method == "GET" || r.Method == "HEAD" || r.Method == "OPTIONS" || r.Method == "TRACE") {
		rBodyBuf, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, caddyhttp.Error(http.StatusBadRequest,
				fmt.Errorf("failed to read request body: %v", err))
		}
		if username != "" && len(rBodyBuf) > 0 {
			addTraffic(username, 0, uint64(len(rBodyBuf)))
		}
		r.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(rBodyBuf)), nil
		}
		r.Body, _ = r.GetBody()
	}

	response, err := h.httpTransport.RoundTrip(r)
	if err := r.Body.Close(); err != nil {
		return nil, caddyhttp.Error(http.StatusBadGateway,
			fmt.Errorf("failed to close response body: %v", err))
	}
	if err != nil {
		if _, ok := err.(caddyhttp.HandlerError); ok {
			return nil, err
		}
		return nil, caddyhttp.Error(http.StatusBadGateway,
			fmt.Errorf("failed to read response: %v", err))
	}
	return response, nil
}

func (h *Handler) roundTripUpstream(r *http.Request, ctx context.Context) (*http.Response, error) {
	if creds := h.upstream.User.String(); creds != "" {
		r.Header.Set(headerProxyAuthorization, "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))
	}
	if r.URL.Port() == "" {
		r.URL.Host = net.JoinHostPort(r.URL.Host, "80")
	}
	upsConn, err := h.dialContext(ctx, "tcp", r.URL.Host)
	if err != nil {
		return nil, caddyhttp.Error(http.StatusBadGateway,
			fmt.Errorf("failed to dial upstream: %v", err))
	}
	if err = r.Write(upsConn); err != nil {
		return nil, caddyhttp.Error(http.StatusBadGateway,
			fmt.Errorf("failed to write upstream request: %v", err))
	}
	response, err := http.ReadResponse(bufio.NewReader(upsConn), r)
	if err != nil {
		return nil, caddyhttp.Error(http.StatusBadGateway,
			fmt.Errorf("failed to read upstream response: %v", err))
	}
	return response, nil
}

func (h Handler) checkCredentials(r *http.Request) error {
	pa := strings.Split(r.Header.Get(headerProxyAuthorization), " ")
	if len(pa) != 2 {
		return errors.New(headerProxyAuthorization + " is required! Expected format: <type> <credentials>")
	}
	if strings.ToLower(pa[0]) != "basic" {
		return errors.New("auth type is not supported")
	}

	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(pa[1])))
	n, err := base64.StdEncoding.Decode(decoded, []byte(pa[1]))
	if err != nil {
		repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
		repl.Set(replacerFieldUserID, "invalidbase64:"+err.Error())
		return err
	}
	decoded = decoded[:n]

	if !utf8.Valid(decoded) {
		repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
		repl.Set(replacerFieldUserID, "invalid::")
		return errors.New("invalid credentials")
	}

	credStr := string(decoded)
	i := strings.IndexByte(credStr, ':')
	if i < 0 {
		repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
		repl.Set(replacerFieldUserID, "invalidformat:"+credStr)
		return errors.New("invalid credentials")
	}
	username := credStr[:i]

	incomingHash := sha256.Sum256(decoded)
	expectedHash, exists := h.authHashes[username]

	var match bool
	if exists {
		match = subtle.ConstantTimeCompare(incomingHash[:], expectedHash[:]) == 1
	} else {
		var zeroHash [32]byte
		subtle.ConstantTimeCompare(incomingHash[:], zeroHash[:])
		match = false
	}

	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if match {
		repl.Set(replacerFieldUserID, username)
		return nil
	}
	repl.Set(replacerFieldUserID, "invalid:"+username)
	return errors.New("invalid credentials")
}

func (h Handler) extractUsername(r *http.Request) string {
	if h.AuthCredentials == nil {
		return ""
	}
	repl, ok := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if !ok {
		return ""
	}
	val, ok := repl.Get(replacerFieldUserID)
	if !ok {
		return ""
	}
	s, ok := val.(string)
	if !ok {
		return ""
	}
	if strings.HasPrefix(s, "invalid") {
		return ""
	}
	if len(s) == 0 || len(s) > 255 {
		return ""
	}
	return s
}

func (h Handler) shouldServePACFile(r *http.Request) bool {
	return len(h.PACPath) > 0 && r.URL.Path == h.PACPath
}

func (h Handler) servePacFile(w http.ResponseWriter, r *http.Request) error {
	fmt.Fprintf(w, pacFile, r.Host)
	// fmt.Fprintf(w, pacFile, h.hostname, h.port)
	return nil
}

// dialContextCheckACL enforces Access Control List and calls fp.DialContext
func (h Handler) dialContextCheckACL(ctx context.Context, network, hostPort string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, caddyhttp.Error(http.StatusBadRequest,
			fmt.Errorf("network %s is not supported", network))
	}

	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		return nil, caddyhttp.Error(http.StatusBadRequest, err)
	}

	if h.upstream != nil {
		conn, err := h.dialContext(ctx, network, hostPort)
		if err != nil {
			return conn, caddyhttp.Error(http.StatusBadGateway, err)
		}
		return conn, nil
	}

	if !h.portIsAllowed(port) {
		return nil, caddyhttp.Error(http.StatusForbidden,
			fmt.Errorf("port %s is not allowed", port))
	}

	if !h.domainIsAllowed(host) {
		return nil, caddyhttp.Error(http.StatusForbidden, fmt.Errorf("disallowed host %s", host))
	}

	return h.dialAllowedIP(ctx, network, host, port)
}

func (h Handler) domainIsAllowed(host string) bool {
	for _, rule := range h.aclRules {
		if _, ok := rule.(*aclDomainRule); ok {
			switch rule.tryMatch(nil, host) {
			case aclDecisionDeny:
				return false
			case aclDecisionAllow:
				return true
			}
		}
	}
	return true // not denied by domain rules, let IP rules decide
}

func (h Handler) dialAllowedIP(ctx context.Context, network, host, port string) (net.Conn, error) {
	IPs, err := net.LookupIP(host)
	if err != nil {
		return nil, caddyhttp.Error(http.StatusBadGateway,
			fmt.Errorf("lookup of %s failed: %v", host, err))
	}

	for _, ip := range IPs {
		if !h.hostIsAllowed(host, ip) {
			continue
		}
		conn, err := h.dialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
	}

	return nil, caddyhttp.Error(http.StatusForbidden, fmt.Errorf("no allowed IP addresses for %s", host))
}

func (h Handler) hostIsAllowed(hostname string, ip net.IP) bool {
	for _, rule := range h.aclRules {
		switch rule.tryMatch(ip, hostname) {
		case aclDecisionDeny:
			return false
		case aclDecisionAllow:
			return true
		}
	}
		h.logger.Warn("no acl match", zap.String("hostname", hostname), zap.Stringer("ip", ip))
	return false
}

func (h Handler) portIsAllowed(port string) bool {
	portInt, err := strconv.Atoi(port)
	if err != nil {
		return false
	}
	if portInt <= 0 || portInt > 65535 {
		return false
	}
	if len(h.AllowedPorts) == 0 {
		return true
	}
	isAllowed := false
	for _, p := range h.AllowedPorts {
		if p == portInt {
			isAllowed = true
			break
		}
	}
	return isAllowed
}

func serveHiddenPage(w http.ResponseWriter, authErr error) error {
	const hiddenPage = `<html>
<head>
  <title>Hidden Proxy Page</title>
</head>
<body>
<h1>Hidden Proxy Page!</h1>
%s<br/>
</body>
</html>`
	const AuthFail = "Please authenticate yourself to the proxy."
	const AuthOk = "Congratulations, you are successfully authenticated to the proxy! Go browse all the things!"

	w.Header().Set("Content-Type", "text/html")
	if authErr != nil {
		w.Header().Set(headerProxyAuthenticate, "Basic realm=\"Caddy Secure Web Proxy\"")
		w.WriteHeader(http.StatusProxyAuthRequired)
		_, _ = w.Write([]byte(fmt.Sprintf(hiddenPage, AuthFail)))
		return authErr
	}
	_, _ = w.Write([]byte(fmt.Sprintf(hiddenPage, AuthOk)))
	return nil
}

// Hijacks the connection from ResponseWriter, writes the response and proxies data between targetConn
// and hijacked connection.
func serveHijack(w http.ResponseWriter, targetConn net.Conn, username string) error {
	clientConn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError,
			fmt.Errorf("hijack failed: %v", err))
	}
	defer clientConn.Close()

	if err := clientConn.SetDeadline(time.Time{}); err != nil {
		return caddyhttp.Error(http.StatusInternalServerError,
			fmt.Errorf("failed to clear connection deadlines: %v", err))
	}

	if n := brw.Reader.Buffered(); n > 0 {
		rbuf, _ := brw.Peek(n)
		_, _ = targetConn.Write(rbuf)
	}

	return dualStream(targetConn, clientConn, clientConn, false, username)
}

const (
	NoPadding        = 0
	AddPadding       = 1
	RemovePadding    = 2
	NumFirstPaddings = 8
)

// Copies data target->clientReader and clientWriter->target, and flushes as needed
// Returns when clientWriter-> target stream is done.
// Caddy should finish writing target -> clientReader.
func dualStream(target net.Conn, clientReader io.ReadCloser, clientWriter io.Writer, padding bool, username string) error {
	stream := func(w io.Writer, r io.Reader, paddingType int, isRx bool) error {
		bufPtr := bufferPool.Get().(*[]byte)
		buf := *bufPtr
		buf = buf[0:cap(buf)]
		n, _err := flushingIoCopy(w, r, buf, paddingType)
		bufferPool.Put(bufPtr)

		if username != "" && n > 0 {
			if isRx {
				addTraffic(username, uint64(n), 0)
			} else {
				addTraffic(username, 0, uint64(n))
			}
		}

		if cw, ok := w.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
		return _err
	}

	goStream := func(dst io.Writer, src io.Reader, padType int, isRx bool) {
		if err := stream(dst, src, padType, isRx); err != nil {
			globalTraffic.mu.RLock()
			if globalTraffic.log != nil {
				globalTraffic.log.Warn("tx stream error", zap.Error(err))
			}
			globalTraffic.mu.RUnlock()
			if c, ok := dst.(net.Conn); ok {
				_ = c.Close()
			}
		}
	}

	txPadType := NoPadding
	rxPadType := NoPadding
	if padding {
		txPadType = RemovePadding
		rxPadType = AddPadding
	}
	go goStream(target, clientReader, txPadType, false)
	return stream(clientWriter, target, rxPadType, true)
}

type countingReadCloser struct {
	rc       io.ReadCloser
	username string
	isRx     bool
}

func (c *countingReadCloser) Read(p []byte) (int, error) {
	n, err := c.rc.Read(p)
	if n > 0 {
		if c.isRx {
			addTraffic(c.username, uint64(n), 0)
		} else {
			addTraffic(c.username, 0, uint64(n))
		}
	}
	return n, err
}

func (c *countingReadCloser) Close() error {
	return c.rc.Close()
}

type closeWriter interface {
	CloseWrite() error
}

func readWithAddPadding(src io.Reader, buf []byte) (int, error) {
	paddingSize := rand.Intn(256)
	maxRead := len(buf) - 3 - paddingSize
	if maxRead < 1 {
		maxRead = 1
	}
	nr, er := src.Read(buf[3 : 3+maxRead])
	if nr > 0 {
		buf[0] = byte(nr / 256)
		buf[1] = byte(nr % 256)
		buf[2] = byte(paddingSize)
		for i := 0; i < paddingSize; i++ {
			buf[3+nr+i] = 0
		}
		nr += 3 + paddingSize
	}
	return nr, er
}

func readWithRemovePadding(src io.Reader, buf []byte) (int, error) {
	nr, er := io.ReadFull(src, buf[0:3])
	if nr < 3 {
		return nr, er
	}
	dataLen := int(buf[0])*256 + int(buf[1])
	paddingSize := int(buf[2])
	if dataLen > len(buf) {
		dataLen = len(buf)
	}
	nr, er = io.ReadFull(src, buf[0:dataLen])
	if nr > 0 {
		var junk [256]byte
		if paddingSize > 256 {
			paddingSize = 256
		}
		_, _ = io.ReadFull(src, junk[0:paddingSize])
	}
	return nr, er
}

// flushingIoCopy is analogous to buffering io.Copy(), but also attempts to flush on each iteration.
// If dst does not implement http.Flusher(e.g. net.TCPConn), it will do a simple io.CopyBuffer().
// Reasoning: http2ResponseWriter will not flush on its own, so we have to do it manually.
func flushingIoCopy(dst io.Writer, src io.Reader, buf []byte, paddingType int) (written int64, err error) {
	var rc *http.ResponseController
	if rw, ok := dst.(http.ResponseWriter); ok {
		rc = http.NewResponseController(rw)
	}
	var numPadding int
	for {
		var nr int
		var er error
		switch {
		case paddingType == AddPadding && numPadding < NumFirstPaddings:
			numPadding++
			nr, er = readWithAddPadding(src, buf)
		case paddingType == RemovePadding && numPadding < NumFirstPaddings:
			numPadding++
			nr, er = readWithRemovePadding(src, buf)
		default:
			nr, er = src.Read(buf)
		}
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if rc != nil {
				if ef := rc.Flush(); ef != nil {
					err = ef
					break
				}
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return
}

// Removes hop-by-hop headers, and writes response into ResponseWriter.
func forwardResponse(w http.ResponseWriter, response *http.Response) error {
	w.Header().Del("Server") // remove Server: Caddy, append via instead
	w.Header().Add("Via", strconv.Itoa(response.ProtoMajor)+"."+strconv.Itoa(response.ProtoMinor)+" caddy")

	for header, values := range response.Header {
		for _, val := range values {
			w.Header().Add(header, val)
		}
	}
	removeHopByHop(w.Header())
	w.WriteHeader(response.StatusCode)
	bufPtr := bufferPool.Get().(*[]byte)
	buf := *bufPtr
	buf = buf[0:cap(buf)]
	_, err := io.CopyBuffer(w, response.Body, buf)
	bufferPool.Put(bufPtr)
	return err
}

func removeHopByHop(header http.Header) {
	connectionHeaders := header.Get("Connection")
	for _, h := range strings.Split(connectionHeaders, ",") {
		header.Del(strings.TrimSpace(h))
	}
	for _, h := range hopByHopHeaders {
		header.Del(h)
	}
}

var hopByHopHeaders = []string{
	"Keep-Alive",
	headerProxyAuthenticate,
	headerProxyAuthorization,
	"Upgrade",
	"Connection",
	"Proxy-Connection",
	"Te",
	"Trailer",
	"Transfer-Encoding",
}

const pacFile = `
function FindProxyForURL(url, host) {
	if (host === "127.0.0.1" || host === "::1" || host === "localhost")
		return "DIRECT";
	return "HTTPS %s";
}
`

var bufferPool = sync.Pool{
	New: func() interface{} {
		buffer := make([]byte, 0, 64*1024)
		return &buffer
	},
}

////// used during provision only

func isLocalhost(hostname string) bool {
	return hostname == "localhost" ||
		hostname == "127.0.0.1" ||
		hostname == "::1"
}

type dialContexter interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// ProbeResistance configures probe resistance.
type ProbeResistance struct {
	Domain string `json:"domain,omitempty"`
}

func readLinesFromFile(filename string) ([]string, error) {
	cleanFilename := filepath.Clean(filename)
	file, err := os.Open(cleanFilename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var hostnames []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		hostnames = append(hostnames, scanner.Text())
	}

	return hostnames, scanner.Err()
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ caddyfile.Unmarshaler       = (*Handler)(nil)
)
