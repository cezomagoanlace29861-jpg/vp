package engine

import (
	"io"
	"net/netip"
	"regexp"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Log lines are shown in the app and end up in screenshots and messages
// asking for help, so they never carry links, addresses or host names: not
// of servers, not of the sites visited, not of the account service.
var (
	linkRe = regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9+.-]*://[^\s"'<>]+`)
	addrRe = regexp.MustCompile(`\[?[0-9a-fA-F]*[:.][0-9a-fA-F:.]*[0-9a-fA-F]\]?(?::\d{1,5})?`)
	hostRe = regexp.MustCompile(`\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(xn--[a-zA-Z0-9-]{1,59}|[a-zA-Z]{2,63})\b(?::\d{1,5})?`)
)

// Redact replaces the links, IP addresses and host names in s.
func Redact(s string) string {
	s = linkRe.ReplaceAllString(s, "[link]")
	s = addrRe.ReplaceAllStringFunc(s, func(m string) string {
		if isAddr(m) {
			return "[address]"
		}
		return m
	})
	return hostRe.ReplaceAllStringFunc(s, func(m string) string {
		host, _, _ := strings.Cut(m, ":")
		// Only names under a real top-level domain: "sing-box.exe" and
		// "geosite-ir.srs" stay.
		tld := strings.ToLower(host[strings.LastIndexByte(host, '.')+1:])
		if _, icann := publicsuffix.PublicSuffix(tld); icann {
			return "[host]"
		}
		return m
	})
}

func isAddr(s string) bool {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().IsValid()
	}
	_, err := netip.ParseAddr(strings.Trim(s, "[]"))
	return err == nil
}

// RedactWriter passes what is written through Redact. Each write is
// treated as whole lines, as the log package writes them.
func RedactWriter(w io.Writer) io.Writer { return redactWriter{w} }

type redactWriter struct{ w io.Writer }

func (r redactWriter) Write(p []byte) (int, error) {
	if _, err := io.WriteString(r.w, Redact(string(p))); err != nil {
		return 0, err
	}
	return len(p), nil
}
