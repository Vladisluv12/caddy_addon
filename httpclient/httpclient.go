// Copyright 2018 Google Inc.
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

// Package httpclient is used by the upstreaming forwardproxy to establish connections to http(s) upstreams.
// it implements x/net/proxy.Dialer interface
package httpclient

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"

	"golang.org/x/net/http2"
)

// HTTPConnectDialer allows to configure one-time use HTTP CONNECT client
type HTTPConnectDialer struct {
	ProxyURL      url.URL
	DefaultHeader http.Header

	// SpkiFP is the expected SHA-256 hash of the upstream proxy's DER-encoded
	// SubjectPublicKeyInfo. When set, the proxy's certificate is verified against
	// this fingerprint instead of relying solely on standard PKI CA roots.
	// This provides certificate pinning for the upstream TLS connection.
	SpkiFP []byte

	Dialer net.Dialer // overridden dialer allow to control establishment of TCP connection

	// overridden DialTLS allows user to control establishment of TLS connection
	// MUST return connection with completed Handshake, and NegotiatedProtocol
	DialTLS func(network string, address string) (net.Conn, string, error)

	EnableH2ConnReuse  bool
	cacheH2Mu          sync.Mutex
	cachedH2ClientConn *http2.ClientConn
	cachedH2RawConn    net.Conn
}

// NewHTTPConnectDialer creates a client to issue CONNECT requests and tunnel traffic via HTTPS proxy.
// proxyURLStr must provide Scheme and Host, may provide credentials and port.
// Example: https://username:password@golang.org:443
func NewHTTPConnectDialer(proxyURLStr string) (*HTTPConnectDialer, error) {
	proxyURL, err := url.Parse(proxyURLStr)
	if err != nil {
		return nil, err
	}

	if proxyURL.Host == "" {
		return nil, errors.New("misparsed `url=" + proxyURLStr +
			"`, make sure to specify full url like https://username:password@hostname.com:443/")
	}

	switch proxyURL.Scheme {
	case "http":
		if proxyURL.Port() == "" {
			proxyURL.Host = net.JoinHostPort(proxyURL.Host, "80")
		}
	case "https":
		if proxyURL.Port() == "" {
			proxyURL.Host = net.JoinHostPort(proxyURL.Host, "443")
		}
	case "":
		return nil, errors.New("specify scheme explicitly (https://)")
	default:
		return nil, errors.New("scheme " + proxyURL.Scheme + " is not supported")
	}

	client := &HTTPConnectDialer{
		ProxyURL:          *proxyURL,
		DefaultHeader:     make(http.Header),
		EnableH2ConnReuse: true,
	}

	if proxyURL.User != nil {
		if proxyURL.User.Username() != "" {
			password, _ := proxyURL.User.Password()
			client.DefaultHeader.Set("Proxy-Authorization", "Basic "+
				base64.StdEncoding.EncodeToString([]byte(proxyURL.User.Username()+":"+password)))
		}
	}
	return client, nil
}

func (c *HTTPConnectDialer) Dial(network, address string) (net.Conn, error) {
	return c.DialContext(context.Background(), network, address)
}

// Users of context.WithValue should define their own types for keys
type ContextKeyHeader struct{}

func (c *HTTPConnectDialer) buildRequest(ctx context.Context, address string) *http.Request {
	req := (&http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Host: address},
		Header: make(http.Header),
		Host:   address,
	}).WithContext(ctx)
	for k, v := range c.DefaultHeader {
		req.Header[k] = v
	}
	if ctxHeader, ok := ctx.Value(ContextKeyHeader{}).(http.Header); ok {
		for k, v := range ctxHeader {
			req.Header[k] = v
		}
	}
	return req
}

func (c *HTTPConnectDialer) tryReuseH2Conn(req *http.Request) (net.Conn, bool) {
	if !c.EnableH2ConnReuse {
		return nil, false
	}
	c.cacheH2Mu.Lock()
	if c.cachedH2ClientConn == nil || c.cachedH2RawConn == nil || !c.cachedH2ClientConn.CanTakeNewRequest() {
		c.cacheH2Mu.Unlock()
		return nil, false
	}
	rc := c.cachedH2RawConn
	cc := c.cachedH2ClientConn
	c.cacheH2Mu.Unlock()

	proxyConn, err := c.connectHttp2(req, rc, cc)
	if err != nil {
		return nil, false
	}
	return proxyConn, true
}

func (c *HTTPConnectDialer) dialToProxy(ctx context.Context, network string) (net.Conn, string, error) {
	switch c.ProxyURL.Scheme {
	case "http":
		rawConn, err := c.Dialer.DialContext(ctx, network, c.ProxyURL.Host)
		return rawConn, "", err
	case "https":
		if c.DialTLS != nil {
			return c.DialTLS(network, c.ProxyURL.Host)
		}
		tlsConf := tls.Config{
			NextProtos: []string{"h2", "http/1.1"},
			ServerName: c.ProxyURL.Hostname(),
			MinVersion: tls.VersionTLS12,
		}
		tlsConn, err := tls.Dial(network, c.ProxyURL.Host, &tlsConf)
		if err != nil {
			return nil, "", err
		}
		if err = tlsConn.Handshake(); err != nil {
			return nil, "", err
		}
		return tlsConn, tlsConn.ConnectionState().NegotiatedProtocol, nil
	default:
		return nil, "", errors.New("scheme " + c.ProxyURL.Scheme + " is not supported")
	}
}

func (c *HTTPConnectDialer) verifySPKI(rawConn net.Conn) error {
	if len(c.SpkiFP) == 0 {
		return nil
	}
	tlsConn, ok := rawConn.(*tls.Conn)
	if !ok {
		rawConn.Close()
		return errors.New("SPKI fingerprint verification requires a TLS connection")
	}
	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		rawConn.Close()
		return errors.New("SPKI fingerprint verification failed: no peer certificates")
	}
	spkiHash := sha256.Sum256(certs[0].RawSubjectPublicKeyInfo)
	if subtle.ConstantTimeCompare(spkiHash[:], c.SpkiFP) != 1 {
		rawConn.Close()
		return errors.New("SPKI fingerprint mismatch: upstream proxy identity not confirmed")
	}
	return nil
}

func (c *HTTPConnectDialer) negotiateCONNECT(req *http.Request, rawConn net.Conn, negotiatedProtocol string) (net.Conn, error) {
	switch negotiatedProtocol {
	case "":
		fallthrough
	case "http/1.1":
		return c.connectHttp1(req, rawConn)
	case "h2":
		t := http2.Transport{}
		h2clientConn, err := t.NewClientConn(rawConn)
		if err != nil {
			rawConn.Close()
			return nil, err
		}
		proxyConn, err := c.connectHttp2(req, rawConn, h2clientConn)
		if err != nil {
			rawConn.Close()
			return nil, err
		}
		if c.EnableH2ConnReuse {
			c.cacheH2Mu.Lock()
			c.cachedH2ClientConn = h2clientConn
			c.cachedH2RawConn = rawConn
			c.cacheH2Mu.Unlock()
		}
		return proxyConn, nil
	default:
		rawConn.Close()
		return nil, errors.New("negotiated unsupported application layer protocol: " + negotiatedProtocol)
	}
}

func (c *HTTPConnectDialer) connectHttp2(req *http.Request, rawConn net.Conn, h2clientConn *http2.ClientConn) (net.Conn, error) {
	req.Proto = "HTTP/2.0"
	req.ProtoMajor = 2
	req.ProtoMinor = 0
	pr, pw := io.Pipe()
	req.Body = pr

	resp, err := h2clientConn.RoundTrip(req)
	if err != nil {
		rawConn.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		rawConn.Close()
		return nil, errors.New("Proxy responded with non 200 code: " + resp.Status)
	}
	return NewHttp2Conn(rawConn, pw, resp.Body), nil
}

func (c *HTTPConnectDialer) connectHttp1(req *http.Request, rawConn net.Conn) (net.Conn, error) {
	req.Proto = "HTTP/1.1"
	req.ProtoMajor = 1
	req.ProtoMinor = 1

	if err := req.Write(rawConn); err != nil {
		rawConn.Close()
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(rawConn), req)
	if err != nil {
		rawConn.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		rawConn.Close()
		return nil, errors.New("Proxy responded with non 200 code: " + resp.Status)
	}
	return rawConn, nil
}

// ctx.Value will be inspected for optional ContextKeyHeader{} key, with `http.Header` value,
// which will be added to outgoing request headers, overriding any colliding c.DefaultHeader
func (c *HTTPConnectDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	req := c.buildRequest(ctx, address)

	if proxyConn, ok := c.tryReuseH2Conn(req); ok {
		return proxyConn, nil
	}

	rawConn, negotiatedProtocol, err := c.dialToProxy(ctx, network)
	if err != nil {
		return nil, err
	}

	if err := c.verifySPKI(rawConn); err != nil {
		return nil, err
	}

	return c.negotiateCONNECT(req, rawConn, negotiatedProtocol)
}

func NewHttp2Conn(c net.Conn, pipedReqBody *io.PipeWriter, respBody io.ReadCloser) net.Conn {
	return &http2Conn{Conn: c, in: pipedReqBody, out: respBody}
}

type http2Conn struct {
	net.Conn
	in  *io.PipeWriter
	out io.ReadCloser
}

func (h *http2Conn) Read(p []byte) (n int, err error) {
	return h.out.Read(p)
}

func (h *http2Conn) Write(p []byte) (n int, err error) {
	return h.in.Write(p)
}

func (h *http2Conn) Close() error {
	inErr := h.in.Close()
	outErr := h.out.Close()

	if inErr != nil {
		return inErr
	}
	return outErr
}

func (h *http2Conn) CloseConn() error {
	return h.Conn.Close()
}

func (h *http2Conn) CloseWrite() error {
	return h.in.Close()
}

func (h *http2Conn) CloseRead() error {
	return h.out.Close()
}
