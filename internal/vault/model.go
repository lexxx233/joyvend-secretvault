// Package vault is Vault's core: the encrypted-JSON credential store, the
// auth-injection templates, the hardened egress pipeline (allowlist + resolve-then-pin
// + reflect-guard), and the hash-chained audit log. See DESIGN.md.
package vault

import "time"

// AuthType selects how a credential's secret is injected (DESIGN.md §4).
type AuthType string

const (
	AuthBearer AuthType = "bearer" // Authorization: Bearer <secret>
	AuthHeader AuthType = "header" // <HeaderName>: <secret>
	AuthBasic  AuthType = "basic"  // Authorization: Basic base64(user:secret)
	AuthCustom AuthType = "custom" // Authorization: <template with ${secret}>
)

// Tier is the approval class for a request (DESIGN.md §5 step 5).
type Tier string

const (
	TierAuto    Tier = "auto"    // run without asking
	TierConfirm Tier = "confirm" // block for a human confirm
	TierDeny    Tier = "deny"    // 403, always
)

// Credential is one stored secret plus its policy. The Secret field is plaintext
// only while unlocked; the whole struct is sealed inside vault.json.enc at rest.
type Credential struct {
	Type          AuthType   `json:"type"`
	Secret        string     `json:"secret"`
	HeaderName    string     `json:"header_name,omitempty"` // type=header
	Username      string     `json:"username,omitempty"`    // type=basic (server-pinned)
	Template      string     `json:"template,omitempty"`    // type=custom, contains ${secret}
	AllowHosts    []string   `json:"allow_hosts"`
	AllowPriv     bool       `json:"allow_private,omitempty"`  // permit RFC1918 egress (explicit opt-in)
	AllowInsecure bool       `json:"allow_insecure,omitempty"` // permit http:// (known plaintext internal target)
	ReadTier      Tier       `json:"read_tier"`                // auto | confirm
	WriteTier     Tier       `json:"write_tier"`               // auto | confirm | deny
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	RatePerMin    int        `json:"rate_per_min,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
}

// CredentialMeta is the agent/GUI-visible view: never the secret, only a salted
// fingerprint (DESIGN.md §2).
type CredentialMeta struct {
	Name        string     `json:"name"`
	Type        AuthType   `json:"type"`
	AllowHosts  []string   `json:"allow_hosts"`
	ReadTier    Tier       `json:"read_tier"`
	WriteTier   Tier       `json:"write_tier"`
	Enabled     bool       `json:"enabled"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	Fingerprint string     `json:"fingerprint"`
	CreatedAt   time.Time  `json:"created_at"`
}

// AuditEntry is one append-only, hash-chained record (DESIGN.md §7). It never holds
// the secret or the response body.
type AuditEntry struct {
	Time       time.Time `json:"t"`
	Credential string    `json:"cred"`
	Method     string    `json:"method"`
	Host       string    `json:"host"`
	Decision   string    `json:"decision"` // allowed|denied|blocked|confirmed|timeout|error
	Tier       string    `json:"tier"`
	Status     int       `json:"status"`
	Bytes      int       `json:"bytes"`
	Source     string    `json:"source"`
	LatencyMS  int64     `json:"latency_ms"`
	PrevHash   string    `json:"prev_hash"`
	Hash       string    `json:"hash"`
}

// Grant is a scoped "remember this decision" auto-approval (reserved for v1.1).
type Grant struct {
	Credential string    `json:"cred"`
	Method     string    `json:"method"`
	Host       string    `json:"host"`
	Expires    time.Time `json:"expires"`
}

// vaultDoc is the on-disk JSON document (sealed as one blob).
type vaultDoc struct {
	Version     int                    `json:"version"`
	FPSalt      []byte                 `json:"fp_salt"` // per-vault salt for fingerprints (sealed, GUI-only)
	Credentials map[string]*Credential `json:"credentials"`
	Grants      []Grant                `json:"grants"`
	Audit       []AuditEntry           `json:"audit"`
}

// CurrentVersion is the vaultDoc schema version (DESIGN.md §1 — replaces migrations).
const CurrentVersion = 1
