package vault

import "testing"

func TestNormalizeHost(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"api.github.com", "api.github.com", true},
		{"API.GitHub.COM", "api.github.com", true},
		{"api.github.com.", "api.github.com", true}, // trailing dot stripped
		{"127.0.0.1", "127.0.0.1", true},
		{"[::1]", "", false}, // brackets aren't a host (caller passes Hostname())
		{"::1", "::1", true},
		{"::ffff:127.0.0.1", "127.0.0.1", true}, // IPv4-mapped canonicalised
		{"2130706433", "", false},               // decimal IP literal → rejected
		{"0x7f000001", "", false},               // hex IP literal → rejected
		{"127.1", "", false},                    // short IP literal → rejected
		{"", "", false},
	}
	for _, c := range cases {
		got, err := normalizeHost(c.in)
		if c.ok && (err != nil || got != c.want) {
			t.Errorf("normalizeHost(%q) = %q,%v; want %q,nil", c.in, got, err, c.want)
		}
		if !c.ok && err == nil {
			t.Errorf("normalizeHost(%q) = %q,nil; want error", c.in, got)
		}
	}
}

func TestHostAllowedLabelAware(t *testing.T) {
	cases := []struct {
		host    string
		allow   []string
		allowed bool
	}{
		{"api.stripe.com", []string{"api.stripe.com"}, true},
		{"api.stripe.com", []string{"api.github.com"}, false},
		// exact must not match a longer attacker host
		{"api.stripe.com.attacker.com", []string{"api.stripe.com"}, false},
		// wildcard matches subdomains...
		{"a.example.com", []string{"*.example.com"}, true},
		{"a.b.example.com", []string{"*.example.com"}, true},
		// ...but not the bare domain, nor a substring-confusion host
		{"example.com", []string{"*.example.com"}, false},
		{"evilexample.com", []string{"*.example.com"}, false},
		{"example.com.attacker.com", []string{"*.example.com"}, false},
		// case-insensitive
		{"API.Stripe.COM", []string{"api.stripe.com"}, true},
	}
	for _, c := range cases {
		h, err := normalizeHost(c.host)
		if err != nil {
			t.Fatalf("normalizeHost(%q): %v", c.host, err)
		}
		if got := hostAllowed(h, c.allow); got != c.allowed {
			t.Errorf("hostAllowed(%q, %v) = %v; want %v", c.host, c.allow, got, c.allowed)
		}
	}
}
