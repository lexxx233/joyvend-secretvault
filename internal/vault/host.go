package vault

import (
	"fmt"
	"net"
	"strings"

	"golang.org/x/net/idna"
)

// normalizeHost canonicalises a hostname for allowlist comparison: lowercase, one
// trailing dot stripped, IDNA→ASCII (so homoglyphs/punycode can't dodge the list).
// IP-literal hosts are returned in canonical net.IP form. (SECURITY.md egress controls.)
func normalizeHost(h string) (string, error) {
	if h == "" {
		return "", fmt.Errorf("empty host")
	}
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	if h == "" {
		return "", fmt.Errorf("empty host")
	}
	if ip := net.ParseIP(h); ip != nil {
		return canonicalIP(ip), nil
	}
	// Reject hosts that look like a numeric/IP-literal attempt but aren't a valid
	// IP (decimal 2130706433, hex 0x7f000001, octal 0177.0.0.1, 127.1, …). These
	// would otherwise be re-interpreted as an IP by the OS resolver and bypass a
	// hostname allowlist (red-team: IP-literal allowlist bypass).
	if looksNumericHost(h) {
		return "", fmt.Errorf("ambiguous numeric host %q", h)
	}
	ascii, err := idna.Lookup.ToASCII(h)
	if err != nil {
		return "", fmt.Errorf("invalid IDNA host %q: %w", h, err)
	}
	return ascii, nil
}

// canonicalIP normalises an IPv4-mapped IPv6 (::ffff:127.0.0.1) down to its IPv4
// form so deny checks see the real address.
func canonicalIP(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

// looksNumericHost reports hosts made only of digits, dots, and 0x/hex that are not
// valid dotted IPs — the classic IP-literal encodings.
func looksNumericHost(h string) bool {
	if strings.HasPrefix(h, "0x") {
		return true
	}
	allNumericish := true
	hasDigit := false
	for _, r := range h {
		switch {
		case r >= '0' && r <= '9':
			hasDigit = true
		case r == '.' || (r >= 'a' && r <= 'f') || r == 'x':
			// hex-ish / dotted
		default:
			allNumericish = false
		}
	}
	// All-digits ("2130706433") or fully hex-ish dotted with no real letters.
	if hasDigit && allNumericish && !strings.ContainsAny(h, "ghijklmnopqrstuvwyz") {
		// A genuine dotted-decimal IPv4 already returned above via net.ParseIP;
		// anything reaching here that is all-numericish is a bypass attempt.
		return true
	}
	return false
}

// normalizePattern canonicalises an allow_hosts entry, which may be a "*.suffix"
// wildcard or an exact host/IP.
func normalizePattern(p string) (string, error) {
	if rest, ok := strings.CutPrefix(p, "*."); ok {
		base, err := normalizeHost(rest)
		if err != nil {
			return "", err
		}
		return "*." + base, nil
	}
	return normalizeHost(p)
}

// hostAllowed reports whether a normalized host matches any allow pattern using
// LABEL-AWARE matching: "*.example.com" matches one-or-more leading labels of
// example.com, never a substring/suffix like "evilexample.com". (Red-team: suffix
// and homoglyph confusion.)
func hostAllowed(host string, patterns []string) bool {
	for _, p := range patterns {
		np, err := normalizePattern(p)
		if err != nil {
			continue
		}
		if base, ok := strings.CutPrefix(np, "*."); ok {
			if strings.HasSuffix(host, "."+base) && len(host) > len(base)+1 {
				return true
			}
			continue
		}
		if host == np {
			return true
		}
	}
	return false
}

func isReservedHeader(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "authorization", "proxy-authorization", "cookie", "host", "content-length":
		return true
	}
	return false
}
