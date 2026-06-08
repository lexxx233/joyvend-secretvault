package vault

import (
	"fmt"
	"regexp"
)

func mustNameRe() *regexp.Regexp {
	return regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
}

// validateCredential checks shape and fills tier defaults. Runs on the control
// plane at Put time (DESIGN.md §2).
func validateCredential(c *Credential) error {
	if c == nil {
		return fmt.Errorf("vault: nil credential")
	}
	switch c.Type {
	case AuthBearer:
		if c.Secret == "" {
			return fmt.Errorf("vault: bearer credential needs a secret")
		}
	case AuthHeader:
		if c.Secret == "" || c.HeaderName == "" {
			return fmt.Errorf("vault: header credential needs header_name and secret")
		}
		if isReservedHeader(c.HeaderName) {
			return fmt.Errorf("vault: header_name %q is reserved", c.HeaderName)
		}
	case AuthBasic:
		if c.Username == "" || c.Secret == "" {
			return fmt.Errorf("vault: basic credential needs username and secret")
		}
	case AuthCustom:
		if c.Secret == "" {
			return fmt.Errorf("vault: custom credential needs a secret")
		}
		if !containsSecretPlaceholder(c.Template) {
			return fmt.Errorf("vault: custom template must contain ${secret}")
		}
	default:
		return fmt.Errorf("vault: unknown auth type %q", c.Type)
	}

	if len(c.AllowHosts) == 0 {
		return fmt.Errorf("vault: allow_hosts must not be empty (the security boundary)")
	}
	for _, h := range c.AllowHosts {
		if _, err := normalizePattern(h); err != nil {
			return fmt.Errorf("vault: invalid allow_hosts entry %q: %w", h, err)
		}
	}

	switch c.ReadTier {
	case "":
		c.ReadTier = TierAuto
	case TierAuto, TierConfirm:
	default:
		return fmt.Errorf("vault: read_tier must be auto or confirm, got %q", c.ReadTier)
	}
	switch c.WriteTier {
	case "":
		c.WriteTier = TierConfirm
	case TierAuto, TierConfirm, TierDeny:
	default:
		return fmt.Errorf("vault: write_tier must be auto, confirm, or deny, got %q", c.WriteTier)
	}
	return nil
}

func containsSecretPlaceholder(t string) bool {
	return len(t) > 0 && indexOf(t, "${secret}") >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
