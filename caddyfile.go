package forwardproxy

import (
	"encoding/base64"
	"log"
	"strconv"
	"strings"

	caddy "github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("forward_proxy", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("forward_proxy", httpcaddyfile.After, "file_server")
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var fp Handler
	err := fp.UnmarshalCaddyfile(h.Dispenser)
	return &fp, err
}

func EncodeAuthCredentials(user, pass string) (result []byte) {
	raw := []byte(user + ":" + pass)
	result = make([]byte, base64.StdEncoding.EncodedLen(len(raw)))
	base64.StdEncoding.Encode(result, raw)
	return
}

func (h *Handler) unmarshalBasicAuth(d *caddyfile.Dispenser) error {
	args := d.RemainingArgs()
	if len(args) != 2 {
		return d.ArgErr()
	}
	if len(args[0]) == 0 {
		return d.Err("empty usernames are not allowed")
	}
	if len(args[1]) == 0 {
		return d.Err("empty passwords are not allowed")
	}
	if strings.Contains(args[0], ":") {
		return d.Err("character ':' in usernames is not allowed")
	}
	if h.AuthCredentials == nil {
		h.AuthCredentials = [][]byte{}
	}
	h.AuthCredentials = append(h.AuthCredentials, EncodeAuthCredentials(args[0], args[1]))
	return nil
}

func (h *Handler) unmarshalPorts(d *caddyfile.Dispenser) error {
	args := d.RemainingArgs()
	if len(args) == 0 {
		return d.ArgErr()
	}
	if len(h.AllowedPorts) != 0 {
		return d.Err("ports subdirective specified twice")
	}
	h.AllowedPorts = make([]int, len(args))
	for i, p := range args {
		intPort, err := strconv.Atoi(p)
		if intPort <= 0 || intPort > 65535 || err != nil {
			return d.Errf("ports are expected to be space-separated and in 0-65535 range, but got: %s", p)
		}
		h.AllowedPorts[i] = intPort
	}
	return nil
}

func (h *Handler) unmarshalProbeResistance(d *caddyfile.Dispenser) error {
	args := d.RemainingArgs()
	if len(args) > 1 {
		return d.ArgErr()
	}
	if len(args) == 1 {
		lowercaseArg := strings.ToLower(args[0])
		if lowercaseArg != args[0] {
			log.Println("[WARNING] Secret domain appears to have uppercase letters in it, which are not visitable")
		}
		h.ProbeResistance = &ProbeResistance{Domain: args[0]}
	} else {
		h.ProbeResistance = &ProbeResistance{}
	}
	return nil
}

func (h *Handler) unmarshalServePAC(d *caddyfile.Dispenser) error {
	args := d.RemainingArgs()
	if len(args) > 1 {
		return d.ArgErr()
	}
	if len(h.PACPath) != 0 {
		return d.Err("serve_pac subdirective specified twice")
	}
	if len(args) == 1 {
		h.PACPath = args[0]
		if !strings.HasPrefix(h.PACPath, "/") {
			h.PACPath = "/" + h.PACPath
		}
	} else {
		h.PACPath = "/proxy.pac"
	}
	return nil
}

func (h *Handler) unmarshalACL(d *caddyfile.Dispenser) error {
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		aclDirective := d.Val()
		args := d.RemainingArgs()
		if len(args) == 0 {
			return d.ArgErr()
		}
		var ruleSubjects []string
		var err error
		aclAllow := false
		switch aclDirective {
		case "allow":
			ruleSubjects = args
			aclAllow = true
		case "allow_file":
			if len(args) != 1 {
				return d.Err("allowfile accepts a single filename argument")
			}
			ruleSubjects, err = readLinesFromFile(args[0])
			if err != nil {
				return err
			}
			aclAllow = true
		case "deny":
			ruleSubjects = args
		case "deny_file":
			if len(args) != 1 {
				return d.Err("denyfile accepts a single filename argument")
			}
			ruleSubjects, err = readLinesFromFile(args[0])
			if err != nil {
				return err
			}
		default:
			return d.Err("expected acl directive: allow/allowfile/deny/denyfile." +
				"got: " + aclDirective)
		}
		ar := ACLRule{Subjects: ruleSubjects, Allow: aclAllow}
		h.ACL = append(h.ACL, ar)
	}
	return nil
}

func (h *Handler) unmarshalNoArgsBool(d *caddyfile.Dispenser) error {
	args := d.RemainingArgs()
	if len(args) != 0 {
		return d.ArgErr()
	}
	return nil
}

func (h *Handler) unmarshalDialTimeout(d *caddyfile.Dispenser) error {
	args := d.RemainingArgs()
	if len(args) != 1 {
		return d.ArgErr()
	}
	timeout, err := caddy.ParseDuration(args[0])
	if err != nil {
		return d.ArgErr()
	}
	if timeout < 0 {
		return d.Err("dial_timeout cannot be negative.")
	}
	h.DialTimeout = caddy.Duration(timeout)
	return nil
}

// UnmarshalCaddyfile unmarshals Caddyfile tokens into h.
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume directive name

	args := d.RemainingArgs()
	if len(args) > 0 {
		return d.ArgErr()
	}
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		subdir := d.Val()

		switch subdir {
		case "basic_auth":
			if err := h.unmarshalBasicAuth(d); err != nil {
				return err
			}

		case "hosts":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return d.ArgErr()
			}
			if len(h.Hosts) != 0 {
				return d.Err("hosts subdirective specified twice")
			}
			h.Hosts = caddyhttp.MatchHost(args)

		case "ports":
			if err := h.unmarshalPorts(d); err != nil {
				return err
			}

		case "hide_ip":
			if err := h.unmarshalNoArgsBool(d); err != nil {
				return err
			}
			h.HideIP = true

		case "hide_via":
			if err := h.unmarshalNoArgsBool(d); err != nil {
				return err
			}
			h.HideVia = true

		case "disable_insecure_upstreams_check":
			if err := h.unmarshalNoArgsBool(d); err != nil {
				return err
			}
			h.DisableInsecureUpstreamsCheck = true

		case "probe_resistance":
			if err := h.unmarshalProbeResistance(d); err != nil {
				return err
			}

		case "serve_pac":
			if err := h.unmarshalServePAC(d); err != nil {
				return err
			}

		case "dial_timeout":
			if err := h.unmarshalDialTimeout(d); err != nil {
				return err
			}

		case "max_idle_conns":
			args := d.RemainingArgs()
			if len(args) != 1 {
				return d.ArgErr()
			}
			val, err := strconv.Atoi(args[0])
			if err != nil {
				return d.ArgErr()
			}
			h.MaxIdleConns = val

		case "max_idle_conns_per_host":
			args := d.RemainingArgs()
			if len(args) != 1 {
				return d.ArgErr()
			}
			val, err := strconv.Atoi(args[0])
			if err != nil {
				return d.ArgErr()
			}
			h.MaxIdleConnsPerHost = val

		case "upstream":
			args := d.RemainingArgs()
			if len(args) != 1 {
				return d.ArgErr()
			}
			if h.Upstream != "" {
				return d.Err("upstream directive specified more than once")
			}
			h.Upstream = args[0]

		case "traffic_file":
			args := d.RemainingArgs()
			if len(args) != 1 {
				return d.ArgErr()
			}
			h.TrafficFile = args[0]

		case "acl":
			if err := h.unmarshalACL(d); err != nil {
				return err
			}

		default:
			return d.ArgErr()
		}
	}
	return nil
}
