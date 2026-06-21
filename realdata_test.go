package forwardproxy

import (
	"fmt"
	"net"
	"runtime"
	"testing"
	"time"
)

const (
	testGeoIPFile   = "testdata/geoip.dat"
	testGeositeFile = "testdata/geosite.dat"
)

func TestRealGeoIPLoad(t *testing.T) {
	var m1, m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)

	start := time.Now()
	reader, err := loadGeoIPFile(testGeoIPFile)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("loadGeoIPFile failed: %v", err)
	}

	runtime.GC()
	runtime.ReadMemStats(&m2)

	allocMB := float64(m2.TotalAlloc-m1.TotalAlloc) / 1024 / 1024
	sysMB := float64(m2.Sys) / 1024 / 1024

	t.Logf("=== GeoIP Load Report ===")
	t.Logf("File size:      22 MB")
	t.Logf("Countries:      %d", len(reader.countries))
	totalCIDRs := 0
	for i := range reader.countries {
		totalCIDRs += len(reader.countries[i].v4) + len(reader.countries[i].v6)
	}
	t.Logf("Total CIDRs:    %d", totalCIDRs)
	t.Logf("Load time:      %v", elapsed)
	t.Logf("Memory alloc:   %.2f MB", allocMB)
	t.Logf("Heap in-use:    %.2f MB", float64(m2.HeapInuse)/1024/1024)
	t.Logf("Sys (total):    %.2f MB", sysMB)

	// Test lookups
	testIPs := []struct {
		ip     string
		wantCC string
	}{
		{"8.8.8.8", "US"},
		{"1.1.1.1", ""},         // Cloudflare, might be AU or US
		{"5.6.7.8", ""},         // unknown
		{"185.199.108.153", ""}, // GitHub
		{"77.88.8.8", "RU"},     // Yandex DNS
	}

	for _, tc := range testIPs {
		ip := net.ParseIP(tc.ip)
		if ip == nil {
			t.Errorf("failed to parse IP %s", tc.ip)
			continue
		}
		cc := reader.lookupCountry(ip)
		if len(tc.wantCC) > 0 && cc != tc.wantCC {
			t.Logf("lookupCountry(%s) = %s (expected %s)", tc.ip, cc, tc.wantCC)
		} else {
			t.Logf("lookupCountry(%s) = %s", tc.ip, cc)
		}
	}

	// Test hasCountry
	if reader.hasCountry(net.ParseIP("8.8.8.8"), "US") {
		t.Log("hasCountry(8.8.8.8, US) = true ✓")
	} else {
		t.Error("hasCountry(8.8.8.8, US) = false, expected true")
	}
}

func TestRealGeositeLoad(t *testing.T) {
	var m1, m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)

	start := time.Now()
	reader, err := loadGeositeFile(testGeositeFile)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("loadGeositeFile failed: %v", err)
	}

	runtime.GC()
	runtime.ReadMemStats(&m2)

	allocMB := float64(m2.TotalAlloc-m1.TotalAlloc) / 1024 / 1024
	sysMB := float64(m2.Sys) / 1024 / 1024

	cats := reader.getCategories()
	totalDomains := 0
	for _, cat := range cats {
		if c, ok := reader.categories[cat]; ok {
			totalDomains += len(c.exact)
		}
	}

	t.Logf("=== Geosite Load Report ===")
	t.Logf("File size:      2.2 MB")
	t.Logf("Categories:     %d", len(cats))
	t.Logf("Total domains:  %d", totalDomains)
	t.Logf("Load time:      %v", elapsed)
	t.Logf("Memory alloc:   %.2f MB", allocMB)
	t.Logf("Heap in-use:    %.2f MB", float64(m2.HeapInuse)/1024/1024)
	t.Logf("Sys (total):    %.2f MB", sysMB)

	// Print some categories
	t.Logf("Sample categories: %v", cats[:min(10, len(cats))])

	// Test domain lookups
	testDomains := []struct {
		domain   string
		category string
	}{
		{"google.com", "google"},
		{"youtube.com", "google"},
		{"baidu.com", "cn"},
		{"qq.com", "cn"},
		{"example.com", ""}, // probably not in any category
	}

	for _, tc := range testDomains {
		if reader.hasCategory(tc.domain, tc.category) {
			t.Logf("hasCategory(%s, %s) = true ✓", tc.domain, tc.category)
		} else {
			t.Logf("hasCategory(%s, %s) = false", tc.domain, tc.category)
		}
	}
}

func TestRealGeoIPMemoryProfile(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping memory profile in short mode")
	}

	// Measure memory before
	runtime.GC()
	var mBefore runtime.MemStats
	runtime.ReadMemStats(&mBefore)

	// Load geoip.dat
	reader, err := loadGeoIPFile(testGeoIPFile)
	if err != nil {
		t.Fatalf("loadGeoIPFile failed: %v", err)
	}

	runtime.GC()
	var mAfter runtime.MemStats
	runtime.ReadMemStats(&mAfter)

	memUsed := float64(mAfter.TotalAlloc-mBefore.TotalAlloc) / 1024 / 1024

	t.Logf("=== GeoIP Memory Profile ===")
	totalCIDRs := 0
	for i := range reader.countries {
		totalCIDRs += len(reader.countries[i].v4) + len(reader.countries[i].v6)
	}
	t.Logf("Countries:       %d", len(reader.countries))
	t.Logf("Total CIDRs:     %d", totalCIDRs)
	t.Logf("Memory allocated: %.2f MB", memUsed)
	t.Logf("Heap alloc:       %.2f MB", float64(mAfter.HeapAlloc)/1024/1024)
	t.Logf("Heap in-use:      %.2f MB", float64(mAfter.HeapInuse)/1024/1024)
	t.Logf("Sys:              %.2f MB", float64(mAfter.Sys)/1024/1024)
	t.Logf("GC cycles:        %d", mAfter.NumGC-mBefore.NumGC)

	// Simulate lookup load
	start := time.Now()
	lookups := 100
	for i := 0; i < lookups; i++ {
		ip := net.IPv4(byte(i%256), byte((i>>8)%256), byte((i>>16)%256), byte((i>>24)%256))
		reader.lookupCountry(ip)
	}
	elapsed := time.Since(start)
	t.Logf("Lookups:          %d in %v (%.0f lookups/sec)", lookups, elapsed, float64(lookups)/elapsed.Seconds())
}

func TestRealCombinedMemoryProfile(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping memory profile in short mode")
	}

	runtime.GC()
	var mBefore runtime.MemStats
	runtime.ReadMemStats(&mBefore)

	// Load both files
	geoipReader, err := loadGeoIPFile(testGeoIPFile)
	if err != nil {
		t.Fatalf("loadGeoIPFile failed: %v", err)
	}
	geositeReader, err := loadGeositeFile(testGeositeFile)
	if err != nil {
		t.Fatalf("loadGeositeFile failed: %v", err)
	}

	runtime.GC()
	var mAfter runtime.MemStats
	runtime.ReadMemStats(&mAfter)

	memUsed := float64(mAfter.TotalAlloc-mBefore.TotalAlloc) / 1024 / 1024

	cats := geositeReader.getCategories()

	t.Logf("=== Combined Memory Profile ===")
	totalCIDRs := 0
	for i := range geoipReader.countries {
		totalCIDRs += len(geoipReader.countries[i].v4) + len(geoipReader.countries[i].v6)
	}
	t.Logf("GeoIP countries: %d, CIDRs: %d", len(geoipReader.countries), totalCIDRs)
	t.Logf("Geosite cats:     %d", len(cats))
	t.Logf("Total alloc:      %.2f MB", memUsed)
	t.Logf("Heap alloc:       %.2f MB", float64(mAfter.HeapAlloc)/1024/1024)
	t.Logf("Heap in-use:      %.2f MB", float64(mAfter.HeapInuse)/1024/1024)
	t.Logf("Sys:              %.2f MB", float64(mAfter.Sys)/1024/1024)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func init() {
	fmt.Println("Test data: geoip.dat=22MB, geosite.dat=2.2MB")
}
