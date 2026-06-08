package vault

import (
	"context"
	"net"
	"testing"
)

func TestIsDeniedIP(t *testing.T) {
	cases := []struct {
		ip           string
		allowPrivate bool
		denied       bool
	}{
		{"8.8.8.8", false, false},               // public
		{"1.1.1.1", false, false},               // public
		{"127.0.0.1", false, true},              // loopback
		{"169.254.169.254", false, true},        // cloud metadata (link-local)
		{"10.0.0.5", false, true},               // RFC1918
		{"192.168.1.1", false, true},            // RFC1918
		{"172.16.0.1", false, true},             // RFC1918
		{"100.64.0.1", false, true},             // CGNAT
		{"0.0.0.0", false, true},                // unspecified
		{"::1", false, true},                    // IPv6 loopback
		{"fe80::1", false, true},                // link-local v6
		{"fc00::1", false, true},                // ULA
		{"::ffff:169.254.169.254", false, true}, // IPv4-mapped metadata
		// allowPrivate lets RFC1918 through but NOT loopback/metadata
		{"10.0.0.5", true, false},
		{"127.0.0.1", true, true},
		{"169.254.169.254", true, true},
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			t.Fatalf("bad test IP %q", c.ip)
		}
		if got := isDeniedIP(ip, c.allowPrivate); got != c.denied {
			t.Errorf("isDeniedIP(%s, priv=%v) = %v; want %v", c.ip, c.allowPrivate, got, c.denied)
		}
	}
}

func TestResolveAndPinRejectsAnyDeniedIP(t *testing.T) {
	// A host resolving to a public AND an internal IP (rebinding-style split) is
	// rejected wholesale.
	resolve := func(ctx context.Context, host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("169.254.169.254")}, nil
	}
	_, err := resolveAndPin(context.Background(), resolve, isDeniedIP, "rebind.test", false)
	if err == nil {
		t.Fatal("expected rejection when one resolved IP is denied")
	}
}

func TestResolveAndPinPinsFirstPublic(t *testing.T) {
	resolve := func(ctx context.Context, host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("203.0.113.7")}, nil
	}
	ip, err := resolveAndPin(context.Background(), resolve, isDeniedIP, "ok.test", false)
	if err != nil || ip.String() != "203.0.113.7" {
		t.Fatalf("resolveAndPin = %v, %v; want 203.0.113.7", ip, err)
	}
}

func TestResolveAndPinLiteralDenied(t *testing.T) {
	_, err := resolveAndPin(context.Background(), nil, isDeniedIP, "169.254.169.254", false)
	if err == nil {
		t.Fatal("metadata IP literal should be denied")
	}
}
