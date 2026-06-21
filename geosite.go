package forwardproxy

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"google.golang.org/protobuf/encoding/protowire"
)

// geositeReader reads V2Ray geosite.dat files and performs domain category lookups.
type geositeReader struct {
	mu         sync.RWMutex
	categories map[string]*geositeCategory // category -> domain set
	loaded     bool
}

// geositeCategory stores domains for a single category with O(1) exact lookup.
type geositeCategory struct {
	exact   map[string]struct{} // exact domain matches (O(1))
	subdoms []string            // domains to check for subdomain suffix matching
}

// loadGeositeFile loads a V2Ray geosite.dat file.
func loadGeositeFile(path string) (*geositeReader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open geosite.dat: %w", err)
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("failed to read geosite.dat: %w", err)
	}

	return parseGeositeData(data)
}

func parseGeositeData(data []byte) (*geositeReader, error) {
	reader := &geositeReader{
		categories: make(map[string]*geositeCategory),
	}

	// Parse top-level Config message: repeated DomainGroup domain = 2;
	buf := data
	for len(buf) > 0 {
		num, typ, n := protowire.ConsumeTag(buf)
		if n < 0 {
			return nil, fmt.Errorf("invalid protobuf tag in geosite.dat")
		}
		buf = buf[n:]

		if num != 2 || typ != protowire.BytesType {
			// Skip non-domain fields
			var err error
			buf, err = skipProtobufField(buf, typ)
			if err != nil {
				return nil, fmt.Errorf("invalid protobuf tag in geosite.dat: %w", err)
			}
			continue
		}

		// Consume the DomainGroup message bytes
		msgBytes, n := protowire.ConsumeBytes(buf)
		if n < 0 {
			return nil, fmt.Errorf("invalid protobuf bytes in geosite.dat")
		}
		buf = buf[n:]

		category, domains, err := parseGeositeEntry(msgBytes)
		if err != nil {
			return nil, err
		}
		if category != "" && len(domains) > 0 {
			cat := &geositeCategory{
				exact: make(map[string]struct{}, len(domains)),
			}
			for _, d := range domains {
				d = strings.TrimPrefix(d, ".")
				cat.exact[d] = struct{}{}
				cat.subdoms = append(cat.subdoms, d)
			}
			reader.categories[category] = cat
		}
	}

	reader.loaded = true
	return reader, nil
}

func parseGeositeEntry(data []byte) (string, []string, error) {
	var category string
	var domains []string

	buf := data
	for len(buf) > 0 {
		num, typ, n := protowire.ConsumeTag(buf)
		if n < 0 {
			return "", nil, fmt.Errorf("invalid protobuf tag in geosite entry")
		}
		buf = buf[n:]

		switch {
		case num == 1 && typ == protowire.BytesType:
			// string type = 1 (category code)
			val, n := protowire.ConsumeBytes(buf)
			if n < 0 {
				return "", nil, fmt.Errorf("invalid type in geosite entry")
			}
			category = string(val)
			buf = buf[n:]

		case num == 2 && typ == protowire.BytesType:
			// repeated Domain domain = 2
			domainBytes, n := protowire.ConsumeBytes(buf)
			if n < 0 {
				return "", nil, fmt.Errorf("invalid domain in geosite entry")
			}
			domain, err := parseGeositeDomain(domainBytes)
			if err != nil {
				return "", nil, err
			}
			if domain != "" {
				domains = append(domains, domain)
			}
			buf = buf[n:]

		default:
			// Skip unknown fields
			var err error
			buf, err = skipProtobufField(buf, typ)
			if err != nil {
				return "", nil, fmt.Errorf("unsupported field in geosite entry: %w", err)
			}
		}
	}

	return category, domains, nil
}

func parseGeositeDomain(data []byte) (string, error) {
	var domainType int32
	var domainValue string

	buf := data
	for len(buf) > 0 {
		num, typ, n := protowire.ConsumeTag(buf)
		if n < 0 {
			return "", fmt.Errorf("invalid protobuf tag in domain")
		}
		buf = buf[n:]

		switch {
		case num == 1 && typ == protowire.VarintType:
			// Type type = 1 (enum)
			val, n := protowire.ConsumeVarint(buf)
			if n < 0 {
				return "", fmt.Errorf("invalid type in domain")
			}
			domainType = int32(val)
			buf = buf[n:]

		case num == 2 && typ == protowire.BytesType:
			// string value = 2
			val, n := protowire.ConsumeBytes(buf)
			if n < 0 {
				return "", fmt.Errorf("invalid value in domain")
			}
			domainValue = string(val)
			buf = buf[n:]

		default:
			// Skip unknown fields
			var err error
			buf, err = skipProtobufField(buf, typ)
			if err != nil {
				return "", fmt.Errorf("unsupported field in domain: %w", err)
			}
		}
	}

	// Type 0 = Plain, Type 1 = Regex, Type 2 = Domain, Type 3 = Full
	// For ACL matching, we support Plain and Domain types
	switch domainType {
	case 0, 2, 3: // Plain, Domain, Full
		return domainValue, nil
	default:
		// Regex and other types are not supported for ACL matching
		return "", nil
	}
}

// hasCategory returns true if the domain belongs to the specified category.
func (r *geositeReader) hasCategory(domain, category string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	cat, ok := r.categories[category]
	if !ok {
		return false
	}

	domain = strings.TrimPrefix(domain, ".")
	// O(1) exact match first
	if _, ok := cat.exact[domain]; ok {
		return true
	}
	// O(n) subdomain suffix match (only when exact match fails)
	for _, d := range cat.subdoms {
		if strings.HasSuffix(domain, "."+d) {
			return true
		}
	}
	return false
}

// getCategories returns all available category codes.
func (r *geositeReader) getCategories() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	categories := make([]string, 0, len(r.categories))
	for cat := range r.categories {
		categories = append(categories, cat)
	}
	return categories
}
