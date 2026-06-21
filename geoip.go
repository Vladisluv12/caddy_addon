package forwardproxy

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"

	"google.golang.org/protobuf/encoding/protowire"
)

// skipProtobufField advances buf past a protobuf field value of the given wire type.
// Returns the advanced buffer, or an error if the data is truncated or the wire type is unknown.
func skipProtobufField(buf []byte, typ protowire.Type) ([]byte, error) {
	switch typ {
	case protowire.VarintType:
		_, n := protowire.ConsumeVarint(buf)
		if n < 0 {
			return nil, fmt.Errorf("invalid varint field")
		}
		return buf[n:], nil
	case protowire.BytesType:
		_, n := protowire.ConsumeBytes(buf)
		if n < 0 {
			return nil, fmt.Errorf("invalid bytes field")
		}
		return buf[n:], nil
	case protowire.Fixed32Type:
		if len(buf) < 4 {
			return nil, fmt.Errorf("truncated fixed32 field")
		}
		return buf[4:], nil
	case protowire.Fixed64Type:
		if len(buf) < 8 {
			return nil, fmt.Errorf("truncated fixed64 field")
		}
		return buf[8:], nil
	default:
		return nil, fmt.Errorf("unsupported protobuf wire type %d", typ)
	}
}

// geoIPReader reads V2Ray geoip.dat files and performs country lookups.
type geoIPReader struct {
	mu      sync.RWMutex
	countries []geoIPCountry
	loaded  bool
}

// geoIPCountry groups all CIDRs for a single country code.
// Country string is stored once per country (not per CIDR).
type geoIPCountry struct {
	countryCode string // stored once, shared by all CIDRs
	v4          []geoIPCIDRv4
	v6          []geoIPCIDRv6
}

// geoIPCIDRv4 is a compact IPv4 CIDR: IP as uint32 + prefix bits.
// No slices, no net.IPNet — just 8 bytes per entry.
type geoIPCIDRv4 struct {
	ip     uint32 // network byte order
	prefix uint8  // CIDR prefix length (0-32)
}

// geoIPCIDRv6 is a compact IPv6 CIDR: IP as [16]byte + prefix bits.
type geoIPCIDRv6 struct {
	ip     [16]byte
	prefix uint8
}

// loadGeoIPFile loads a V2Ray geoip.dat file via mmap.
func loadGeoIPFile(path string) (*geoIPReader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open geoip.dat: %w", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat geoip.dat: %w", err)
	}
	size := info.Size()
	if size == 0 {
		return &geoIPReader{}, nil
	}

	b, err := syscall.Mmap(int(f.Fd()), 0, int(size), syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("failed to mmap geoip.dat: %w", err)
	}
	defer syscall.Munmap(b)

	return parseGeoIPData(b)
}

// parseGeoIPData parses the protobuf and groups CIDRs by country.
func parseGeoIPData(data []byte) (*geoIPReader, error) {
	reader := &geoIPReader{}

	// intern map: deduplicates country code strings
	intern := make(map[string]string)

	// Temporary: collect all raw entries before grouping
	type rawEntry struct {
		countryCode string
		v4          []geoIPCIDRv4
		v6          []geoIPCIDRv6
	}
	var raw []rawEntry

	buf := data
	for len(buf) > 0 {
		num, typ, n := protowire.ConsumeTag(buf)
		if n < 0 {
			return nil, fmt.Errorf("invalid protobuf tag in geoip.dat")
		}
		buf = buf[n:]

		if num != 1 || typ != protowire.BytesType {
			var err error
			buf, err = skipProtobufField(buf, typ)
			if err != nil {
				return nil, fmt.Errorf("invalid protobuf tag in geoip.dat: %w", err)
			}
			continue
		}

		msgBytes, n := protowire.ConsumeBytes(buf)
		if n < 0 {
			return nil, fmt.Errorf("invalid protobuf bytes in geoip.dat")
		}
		buf = buf[n:]

		entry, err := parseGeoIPEntry(msgBytes)
		if err != nil {
			return nil, err
		}
		if entry != nil {
			// Intern country code
			if canonical, ok := intern[entry.countryCode]; ok {
				entry.countryCode = canonical
			} else {
				intern[entry.countryCode] = entry.countryCode
			}
			raw = append(raw, rawEntry{
				countryCode: entry.countryCode,
				v4:          entry.v4,
				v6:          entry.v6,
			})
		}
	}

	// Group by country code
	grouped := make(map[string]*geoIPCountry, len(intern))
	for i := range raw {
		cc := raw[i].countryCode
		c, ok := grouped[cc]
		if !ok {
			c = &geoIPCountry{countryCode: cc}
			grouped[cc] = c
		}
		c.v4 = append(c.v4, raw[i].v4...)
		c.v6 = append(c.v6, raw[i].v6...)
	}

	reader.countries = make([]geoIPCountry, 0, len(grouped))
	for _, c := range grouped {
		reader.countries = append(reader.countries, *c)
	}
	reader.loaded = true
	return reader, nil
}

type rawGeoIPEntry struct {
	countryCode string
	v4          []geoIPCIDRv4
	v6          []geoIPCIDRv6
}

func parseGeoIPEntry(data []byte) (*rawGeoIPEntry, error) {
	var countryCode string
	var v4 []geoIPCIDRv4
	var v6 []geoIPCIDRv6

	buf := data
	for len(buf) > 0 {
		num, typ, n := protowire.ConsumeTag(buf)
		if n < 0 {
			return nil, fmt.Errorf("invalid protobuf tag in geoip entry")
		}
		buf = buf[n:]

		switch {
		case num == 1 && typ == protowire.BytesType:
			val, n := protowire.ConsumeBytes(buf)
			if n < 0 {
				return nil, fmt.Errorf("invalid country_code in geoip entry")
			}
			countryCode = string(val)
			buf = buf[n:]

		case num == 2 && typ == protowire.BytesType:
			cidrBytes, n := protowire.ConsumeBytes(buf)
			if n < 0 {
				return nil, fmt.Errorf("invalid cidr in geoip entry")
			}
			v4c, v6c, err := parseGeoIPCIDRCompact(cidrBytes)
			if err != nil {
				return nil, err
			}
			v4 = append(v4, v4c...)
			v6 = append(v6, v6c...)
			buf = buf[n:]

		case num == 3 && typ == protowire.VarintType:
			_, n := protowire.ConsumeVarint(buf)
			buf = buf[n:]

		default:
			var err error
			buf, err = skipProtobufField(buf, typ)
			if err != nil {
				return nil, fmt.Errorf("unsupported field in geoip entry: %w", err)
			}
		}
	}

	if countryCode == "" || (len(v4) == 0 && len(v6) == 0) {
		return nil, nil
	}
	return &rawGeoIPEntry{countryCode: countryCode, v4: v4, v6: v6}, nil
}

// parseGeoIPCIDRCompact parses a CIDR protobuf message into compact form.
func parseGeoIPCIDRCompact(data []byte) ([]geoIPCIDRv4, []geoIPCIDRv6, error) {
	var ip []byte
	var prefix int32

	buf := data
	for len(buf) > 0 {
		num, typ, n := protowire.ConsumeTag(buf)
		if n < 0 {
			return nil, nil, fmt.Errorf("invalid protobuf tag in CIDR")
		}
		buf = buf[n:]

		switch {
		case num == 1 && typ == protowire.BytesType:
			ipBytes, n := protowire.ConsumeBytes(buf)
			if n < 0 {
				return nil, nil, fmt.Errorf("invalid ip in CIDR")
			}
			ip = ipBytes
			buf = buf[n:]

		case num == 2 && typ == protowire.VarintType:
			val, n := protowire.ConsumeVarint(buf)
			if n < 0 {
				return nil, nil, fmt.Errorf("invalid prefix in CIDR")
			}
			prefix = int32(val)
			buf = buf[n:]

		default:
			var err error
			buf, err = skipProtobufField(buf, typ)
			if err != nil {
				return nil, nil, fmt.Errorf("unsupported field in CIDR: %w", err)
			}
		}
	}

	if len(ip) == 4 {
		return []geoIPCIDRv4{{
			ip:     binary.BigEndian.Uint32(ip),
			prefix: uint8(prefix),
		}}, nil, nil
	}
	if len(ip) == 16 {
		var b [16]byte
		copy(b[:], ip)
		return nil, []geoIPCIDRv6{{
			ip:     b,
			prefix: uint8(prefix),
		}}, nil
	}
	return nil, nil, nil
}

// lookupCountry returns the country code for the given IP, or "" if not found.
func (r *geoIPReader) lookupCountry(ip net.IP) string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ip4 := ip.To4()
	if ip4 != nil {
		return r.lookupCountryV4(binary.BigEndian.Uint32(ip4))
	}
	return r.lookupCountryV6(ip)
}

func (r *geoIPReader) lookupCountryV4(ip uint32) string {
	for i := range r.countries {
		c := &r.countries[i]
		for j := range c.v4 {
			if cidrMatchV4(ip, &c.v4[j]) {
				return c.countryCode
			}
		}
	}
	return ""
}

func (r *geoIPReader) lookupCountryV6(ip net.IP) string {
	if len(ip) != 16 {
		return ""
	}
	var ipArr [16]byte
	copy(ipArr[:], ip)

	for i := range r.countries {
		c := &r.countries[i]
		for j := range c.v6 {
			if cidrMatchV6(ipArr, &c.v6[j]) {
				return c.countryCode
			}
		}
	}
	return ""
}

// cidrMatchV4 checks if ip is in the CIDR range. No allocations.
func cidrMatchV4(ip uint32, c *geoIPCIDRv4) bool {
	if c.prefix == 0 {
		return true
	}
	mask := uint32(0xFFFFFFFF) << (32 - c.prefix)
	return ip&mask == c.ip&mask
}

// cidrMatchV6 checks if ip is in the CIDR range. No allocations.
func cidrMatchV6(ip [16]byte, c *geoIPCIDRv6) bool {
	if c.prefix == 0 {
		return true
	}
	bits := c.prefix
	for i := 0; i < 16 && bits > 0; i++ {
		b := uint8(bits)
		if b > 8 {
			b = 8
		}
		mask := uint8(0xFF) << (8 - b)
		if ip[i]&mask != c.ip[i]&mask {
			return false
		}
		bits -= b
	}
	return true
}

// hasCountry returns true if the given IP belongs to the specified country.
func (r *geoIPReader) hasCountry(ip net.IP, country string) bool {
	return r.lookupCountry(ip) == country
}

// countCIDRs returns the total number of CIDR entries across all countries.
func (r *geoIPReader) countCIDRs() int {
	n := 0
	for i := range r.countries {
		n += len(r.countries[i].v4) + len(r.countries[i].v6)
	}
	return n
}
