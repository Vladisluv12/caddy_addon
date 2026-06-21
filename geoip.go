package forwardproxy

import (
	"fmt"
	"io"
	"net"
	"os"
	"sync"

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
	entries []geoIPNet
	loaded  bool
}

type geoIPNet struct {
	countryCode string
	ipNet       net.IPNet
}

// loadGeoIPFile loads a V2Ray geoip.dat file.
func loadGeoIPFile(path string) (*geoIPReader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open geoip.dat: %w", err)
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("failed to read geoip.dat: %w", err)
	}

	return parseGeoIPData(data)
}

func parseGeoIPData(data []byte) (*geoIPReader, error) {
	reader := &geoIPReader{}

	// Parse top-level Config message: repeated GeoIP geoip = 1;
	buf := data
	for len(buf) > 0 {
		num, typ, n := protowire.ConsumeTag(buf)
		if n < 0 {
			return nil, fmt.Errorf("invalid protobuf tag in geoip.dat")
		}
		buf = buf[n:]

		if num != 1 || typ != protowire.BytesType {
			// Skip non-geoip fields
			var err error
			buf, err = skipProtobufField(buf, typ)
			if err != nil {
				return nil, fmt.Errorf("invalid protobuf tag in geoip.dat: %w", err)
			}
			continue
		}

		// Consume the GeoIP message bytes
		msgBytes, n := protowire.ConsumeBytes(buf)
		if n < 0 {
			return nil, fmt.Errorf("invalid protobuf bytes in geoip.dat")
		}
		buf = buf[n:]

		entry, err := parseGeoIPEntry(msgBytes)
		if err != nil {
			return nil, err
		}
		reader.entries = append(reader.entries, entry...)
	}

	reader.loaded = true
	return reader, nil
}

func parseGeoIPEntry(data []byte) ([]geoIPNet, error) {
	var countryCode string
	var cidrs []geoIPCIDR

	buf := data
	for len(buf) > 0 {
		num, typ, n := protowire.ConsumeTag(buf)
		if n < 0 {
			return nil, fmt.Errorf("invalid protobuf tag in geoip entry")
		}
		buf = buf[n:]

		switch {
		case num == 1 && typ == protowire.BytesType:
			// string country_code = 1
			val, n := protowire.ConsumeBytes(buf)
			if n < 0 {
				return nil, fmt.Errorf("invalid country_code in geoip entry")
			}
			countryCode = string(val)
			buf = buf[n:]

		case num == 2 && typ == protowire.BytesType:
			// repeated CIDR cidr = 2
			cidrBytes, n := protowire.ConsumeBytes(buf)
			if n < 0 {
				return nil, fmt.Errorf("invalid cidr in geoip entry")
			}
			cidr, err := parseGeoIPCIDR(cidrBytes)
			if err != nil {
				return nil, err
			}
			cidrs = append(cidrs, *cidr)
			buf = buf[n:]

		case num == 3 && typ == protowire.VarintType:
			// bool reverse_match = 3
			_, n := protowire.ConsumeVarint(buf)
			buf = buf[n:]

		default:
			// Skip unknown fields
			var err error
			buf, err = skipProtobufField(buf, typ)
			if err != nil {
				return nil, fmt.Errorf("unsupported field in geoip entry: %w", err)
			}
		}
	}

	var results []geoIPNet
	for _, cidr := range cidrs {
		var ipNet net.IPNet
		if len(cidr.ip) == 4 {
			ipNet = net.IPNet{
				IP:   cidr.ip,
				Mask: net.CIDRMask(int(cidr.prefix), 32),
			}
		} else if len(cidr.ip) == 16 {
			ipNet = net.IPNet{
				IP:   cidr.ip,
				Mask: net.CIDRMask(int(cidr.prefix), 128),
			}
		} else {
			continue
		}
		results = append(results, geoIPNet{
			countryCode: countryCode,
			ipNet:       ipNet,
		})
	}
	return results, nil
}

type geoIPCIDR struct {
	ip     []byte
	prefix int32
}

func parseGeoIPCIDR(data []byte) (*geoIPCIDR, error) {
	cidr := &geoIPCIDR{}
	buf := data
	for len(buf) > 0 {
		num, typ, n := protowire.ConsumeTag(buf)
		if n < 0 {
			return nil, fmt.Errorf("invalid protobuf tag in CIDR")
		}
		buf = buf[n:]

		switch {
		case num == 1 && typ == protowire.BytesType:
			ipBytes, n := protowire.ConsumeBytes(buf)
			if n < 0 {
				return nil, fmt.Errorf("invalid ip in CIDR")
			}
			cidr.ip = make([]byte, len(ipBytes))
			copy(cidr.ip, ipBytes)
			buf = buf[n:]

		case num == 2 && typ == protowire.VarintType:
			val, n := protowire.ConsumeVarint(buf)
			if n < 0 {
				return nil, fmt.Errorf("invalid prefix in CIDR")
			}
			cidr.prefix = int32(val)
			buf = buf[n:]

		default:
			var err error
			buf, err = skipProtobufField(buf, typ)
			if err != nil {
				return nil, fmt.Errorf("unsupported field in CIDR: %w", err)
			}
		}
	}
	return cidr, nil
}

// lookupCountry returns the country code for the given IP, or "" if not found.
func (r *geoIPReader) lookupCountry(ip net.IP) string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, entry := range r.entries {
		if entry.ipNet.Contains(ip) {
			return entry.countryCode
		}
	}
	return ""
}

// hasCountry returns true if the given IP belongs to the specified country.
func (r *geoIPReader) hasCountry(ip net.IP, country string) bool {
	return r.lookupCountry(ip) == country
}
