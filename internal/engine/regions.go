package engine

import (
	"path/filepath"
	"strings"
)

// region is a place whose own sites can be opened directly instead of
// through the VPN ("bypass local sites"). Sites of the region are matched by
// top-level domain, by a domain list, by the address ranges of the region,
// and by a list of names learned while connected (learn.go).
type region struct {
	Code     string   // ISO 3166-1 code, the value of Settings.Bypass
	Name     string   // shown in the settings
	Suffixes []string // top-level domains that always belong to the region
	// Subnet is a block of the region's addresses sent along with DNS
	// lookups (EDNS client subnet), so sites that answer each country with
	// its own servers name their servers in the region; those then match
	// the region's address list and open directly on the first visit.
	// Without it they name servers near the VPN server and the site sees
	// a foreign visitor, which many of them refuse.
	Subnet string
	// Extra are sites of the region missing from its domain list; each
	// also covers its subdomains.
	Extra []string
	// Shared are names in the region's domain list that are shared hosting
	// or dynamic DNS for anyone in the world: their sites are never opened
	// directly, or looked up with the region's resolver, by name.
	Shared []string
}

// regions are the choices, in the order they are listed.
var regions = []region{
	{Code: "CN", Name: "China", Suffixes: []string{".cn", ".xn--fiqs8s", ".xn--fiqz9s"}},
	{Code: "IR", Name: "Iran", Suffixes: []string{".ir", ".xn--mgba3a4f16a"}, Subnet: "2.176.0.0/24", // TCI
		Extra:  []string{"aparatcdn.com", "abrarvan.com", "snappmarket.com", "ofogh-kourosh.com", "excoino.com", "chabok.io", "behnevis.com"},
		Shared: []string{"co.com", "ct.ws", "epizy.com", "dyndns.org", "info.com", "uni.me"}},
}

// names are the domain suffixes the region's rules always match: its
// top-level domains and Extra (sing-box's domain_suffix matches a name and
// its subdomains, never a longer word).
func (r region) names() []string { return append(append([]string{}, r.Suffixes...), r.Extra...) }

// owns reports whether host is the region's by its name alone.
func (r region) owns(host string) bool {
	for _, s := range r.Suffixes {
		if strings.HasSuffix(host, s) {
			return true
		}
	}
	for _, d := range r.Extra {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

func findRegion(code string) (region, bool) {
	for _, r := range regions {
		if r.Code == code {
			return r, true
		}
	}
	return region{}, false
}

// lower is the code in the names of the region's rule-set files.
func (r region) lower() string {
	b := []byte(r.Code)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

// geoSiteTag, geoIPTag and learnedTag name the region's rule sets in the
// core's config; the files are <tag>.srs, <tag>.srs and <tag>.json.
func (r region) geoSiteTag() string { return "geosite-" + r.lower() }
func (r region) geoIPTag() string   { return "geoip-" + r.lower() }
func (r region) learnedTag() string { return "learned-" + r.lower() }

func (r region) geoIPFile(dir string) string   { return filepath.Join(dir, r.geoIPTag()+".srs") }
func (r region) learnedFile(dir string) string { return filepath.Join(dir, r.learnedTag()+".json") }

// RegionInfo is a region the user can choose to bypass.
type RegionInfo struct{ Code, Name string }

// Regions lists the choices for Settings.Bypass.
func Regions() []RegionInfo {
	out := make([]RegionInfo, len(regions))
	for i, r := range regions {
		out[i] = RegionInfo{r.Code, r.Name}
	}
	return out
}
