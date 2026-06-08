package vault

import (
	"context"
	"fmt"
	"net"
)

// nat64Prefix is 64:ff9b::/96 — would let ::ffff-style tricks reach an IPv4 target.
var nat64Prefix = mustCIDR("64:ff9b::/96")

// cgnat is 100.64.0.0/10 (RFC 6598), not covered by net.IP.IsPrivate.
var cgnat = mustCIDR("100.64.0.0/10")

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

// isDeniedIP reports whether an IP is off-limits for credentialed egress. Loopback,
// link-local (incl. 169.254.169.254 metadata), multicast, unspecified, ULA, NAT64,
// and CGNAT are always denied; other private (RFC1918) is denied unless the
// credential explicitly opts in via allow_private. (SECURITY.md §"resolve-then-pin".)
func isDeniedIP(ip net.IP, allowPrivate bool) bool {
	if ip == nil {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsInterfaceLocalMulticast() {
		return true
	}
	if nat64Prefix.Contains(ip) {
		return true
	}
	if allowPrivate {
		return false
	}
	return ip.IsPrivate() || cgnat.Contains(ip)
}

// resolveAndPin resolves host once and returns a single pinned IP to dial. If ANY
// resolved address is in a deny range, the whole request is rejected (a host that
// resolves partly-internal is treated as hostile). Anti-rebinding: the caller dials
// this exact IP and the transport never re-resolves. deny is injectable for tests.
func resolveAndPin(ctx context.Context, resolve resolverFunc, deny denyFunc, host string, allowPrivate bool) (net.IP, error) {
	if lit := net.ParseIP(host); lit != nil {
		if deny(lit, allowPrivate) {
			return nil, errSSRFBlocked
		}
		return lit, nil
	}
	ips, err := resolve(ctx, host)
	if err != nil {
		return nil, errDNS
	}
	if len(ips) == 0 {
		return nil, errDNS
	}
	for _, ip := range ips {
		if deny(ip, allowPrivate) {
			return nil, errSSRFBlocked
		}
	}
	return ips[0], nil
}

type resolverFunc func(ctx context.Context, host string) ([]net.IP, error)
type denyFunc func(ip net.IP, allowPrivate bool) bool

func defaultResolve(ctx context.Context, host string) ([]net.IP, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]net.IP, len(addrs))
	for i, a := range addrs {
		out[i] = a.IP
	}
	return out, nil
}

// pinnedDialContext returns a DialContext that ignores the address net/http hands it
// and connects only to the pre-validated pinned IP (preserving the original port).
func pinnedDialContext(pinned net.IP) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("bad addr")
		}
		var d net.Dialer
		return d.DialContext(ctx, network, net.JoinHostPort(pinned.String(), port))
	}
}
