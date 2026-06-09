package vault

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// FetchRequest is what the agent sends to POST /v1/vault/fetch (DESIGN.md §5).
type FetchRequest struct {
	Credential       string            `json:"credential"`
	Method           string            `json:"method"`
	URL              string            `json:"url"`
	Headers          map[string]string `json:"headers,omitempty"`
	Body             string            `json:"body,omitempty"`
	BodyB64          string            `json:"body_b64,omitempty"`
	MaxResponseBytes int64             `json:"max_response_bytes,omitempty"`
}

// FetchResponse is what comes back — the secret is never present.
type FetchResponse struct {
	Status    int                 `json:"status"`
	Headers   map[string][]string `json:"headers"`
	Body      string              `json:"body"`
	Truncated bool                `json:"truncated"`
	AuditID   string              `json:"audit_id"`
}

// ConfirmRequest is shown to the human for a write-tier approval.
type ConfirmRequest struct {
	Credential string
	Method     string
	Host       string
}

// Approver blocks until a human approves/denies a write, or the context is done.
type Approver interface {
	Confirm(ctx context.Context, r ConfirmRequest) (bool, error)
}

// ApproverFunc adapts a function to Approver.
type ApproverFunc func(ctx context.Context, r ConfirmRequest) (bool, error)

func (f ApproverFunc) Confirm(ctx context.Context, r ConfirmRequest) (bool, error) { return f(ctx, r) }

// Engine runs the hardened egress pipeline over a Store.
type Engine struct {
	store    *Store
	approver Approver
	now      func() time.Time
	resolve  resolverFunc
	deny     denyFunc
	newRT    func(pinned net.IP) http.RoundTripper
	limiter  *limiter
	timeout  time.Duration
	maxBytes int64
}

// NewEngine builds an Engine with production defaults.
func NewEngine(store *Store, approver Approver) *Engine {
	now := time.Now
	return &Engine{
		store:    store,
		approver: approver,
		now:      now,
		resolve:  defaultResolve,
		deny:     isDeniedIP,
		newRT:    defaultTransport,
		limiter:  newLimiter(now),
		timeout:  10 * time.Second,
		maxBytes: 10 << 20,
	}
}

// SetEgressDenyForTest overrides the IP deny policy so a test can reach a loopback
// upstream (production always denies loopback). TEST ONLY.
func (e *Engine) SetEgressDenyForTest(fn func(ip net.IP, allowPrivate bool) bool) { e.deny = fn }

func defaultTransport(pinned net.IP) http.RoundTripper {
	return &http.Transport{
		DialContext:       pinnedDialContext(pinned),
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
		DisableKeepAlives: true,
		ForceAttemptHTTP2: true,
	}
}

func noRedirect(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }

// Fetch runs the pipeline (DESIGN.md §5) and returns the upstream response with the
// secret never present. source is the caller's address (for the audit row).
func (e *Engine) Fetch(ctx context.Context, source string, fr FetchRequest) (FetchResponse, *fetchError) {
	start := e.now()
	method := strings.ToUpper(strings.TrimSpace(fr.Method))
	if method == "" {
		method = "GET"
	}

	audit := func(decision, tier, host string, status, nbytes int) string {
		ent := AuditEntry{
			Time: e.now().UTC(), Credential: fr.Credential, Method: method, Host: host,
			Decision: decision, Tier: tier, Status: status, Bytes: nbytes, Source: source,
			LatencyMS: e.now().Sub(start).Milliseconds(),
		}
		_ = e.store.AppendAudit(ent)
		return ent.Hash
	}
	fail := func(host string, fe *fetchError) (FetchResponse, *fetchError) {
		id := audit("denied", "", host, fe.Status, 0)
		return FetchResponse{AuditID: id}, fe
	}

	// 1. credential state
	cred, enabled, ok := e.store.lookup(fr.Credential)
	if !ok {
		return fail("", errNoCred)
	}
	if !enabled {
		return fail("", errCredDisabled)
	}
	if cred.ExpiresAt != nil && e.now().After(*cred.ExpiresAt) {
		return fail("", errCredExpired)
	}

	// 2. parse + scheme + normalize host (reject userinfo)
	u, err := url.Parse(fr.URL)
	if err != nil || u.Host == "" {
		return fail("", errBadURL)
	}
	if u.User != nil {
		return fail("", errBadURL)
	}
	if u.Scheme == "http" {
		if !cred.AllowInsecure {
			return fail("", errInsecure)
		}
	} else if u.Scheme != "https" {
		return fail("", errBadURL)
	}
	// port: a credential that opted into PRIVATE egress (allow_private) is restricted to
	// the scheme's standard port, so the agent can't turn Vault into an authenticated
	// connector to SSH/Redis/Postgres/etc. on an internal allowlisted host. Public-host
	// credentials keep arbitrary ports (the host allowlist + public internet bound them).
	if cred.AllowPriv {
		if p := u.Port(); p != "" && p != "443" && p != "80" {
			return fail("", errBadURL)
		}
	}
	host, err := normalizeHost(u.Hostname())
	if err != nil {
		return fail("", errBadURL)
	}

	// 3. allowlist (label-aware, normalized)
	if !hostAllowed(host, cred.AllowHosts) {
		return fail(host, errNotAllowed)
	}

	// 4. resolve-then-pin egress
	pinned, ferr := resolveAndPin(ctx, e.resolve, e.deny, host, cred.AllowPriv)
	if ferr != nil {
		return fail(host, ferr.(*fetchError))
	}

	// 5. tier
	tier := classifyTier(cred, method)
	if tier == TierDeny {
		return fail(host, errDenied)
	}
	decision := "allowed"
	if tier == TierConfirm {
		approved, aerr := e.approver.Confirm(ctx, ConfirmRequest{Credential: fr.Credential, Method: method, Host: host})
		if aerr != nil || !approved {
			id := audit("blocked", string(tier), host, errApproval.Status, 0)
			return FetchResponse{AuditID: id}, errApproval
		}
		decision = "confirmed"
	}

	// 6. rate
	if !e.limiter.allow(fr.Credential, cred.RatePerMin) {
		return fail(host, errRateLimited)
	}

	// 7. build outgoing request from scratch (strip-then-inject)
	hdr, herr := buildHeaders(fr.Headers, injectHeaderName(cred))
	if herr != nil {
		return fail(host, errBadHeader)
	}
	body, berr := requestBody(fr)
	if berr != nil {
		return fail(host, errBadURL)
	}
	// outbound exfil guard: the agent must not smuggle THIS credential's secret out
	if outboundContainsSecret(cred, fr, body) {
		return fail(host, errExfil)
	}
	injected := injectAuth(cred, hdr)

	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return fail(host, errBadURL)
	}
	req.Header = hdr

	// 8. forward — pinned transport, no redirect follow, capped
	client := &http.Client{Transport: e.newRT(pinned), CheckRedirect: noRedirect, Timeout: e.timeout}
	resp, err := client.Do(req)
	if err != nil {
		return fail(host, errUpstream) // never surface err: it embeds the URL
	}
	defer resp.Body.Close()

	// The reflect-guard can only scan a body it can read. Go transparently decompresses
	// the gzip it negotiated (Accept-Encoding is stripped from the agent), clearing
	// Content-Encoding. If a (possibly hostile) upstream still returns a non-identity
	// encoding it chose unsolicited (br/zstd/deflate), the body is opaque to the scanner
	// — fail closed rather than hand the agent an unscannable, possibly secret-bearing body.
	if ce := resp.Header.Get("Content-Encoding"); ce != "" && !strings.EqualFold(ce, "identity") {
		return fail(host, errReflect)
	}

	max := e.maxBytes
	if fr.MaxResponseBytes > 0 && fr.MaxResponseBytes < max {
		max = fr.MaxResponseBytes
	}
	respBody, truncated := readCapped(resp.Body, max)

	// 9. sanitize response
	needles := secretNeedles(injected)
	outHeaders := sanitizeRespHeaders(resp.Header, cred, needles)
	if containsAny(respBody, needles) {
		return fail(host, errReflect)
	}

	id := audit(decision, string(tier), host, resp.StatusCode, len(respBody))
	return FetchResponse{
		Status:    resp.StatusCode,
		Headers:   outHeaders,
		Body:      string(respBody),
		Truncated: truncated,
		AuditID:   id,
	}, nil
}

func classifyTier(c *Credential, method string) Tier {
	switch method {
	case "GET", "HEAD":
		if c.ReadTier == "" {
			return TierAuto
		}
		return c.ReadTier
	default:
		if c.WriteTier == "" {
			return TierConfirm
		}
		return c.WriteTier
	}
}

func requestBody(fr FetchRequest) ([]byte, error) {
	if fr.BodyB64 != "" {
		return base64.StdEncoding.DecodeString(fr.BodyB64)
	}
	return []byte(fr.Body), nil
}

// outboundContainsSecret rejects a request that carries this credential's own secret
// in the agent-supplied url/headers/body (a naive smuggle). The secret should only
// appear via server-side injection.
func outboundContainsSecret(c *Credential, fr FetchRequest, body []byte) bool {
	if len(c.Secret) < 6 {
		return false // too short to scan without false positives
	}
	sec := []byte(c.Secret)
	if bytes.Contains([]byte(fr.URL), sec) || bytes.Contains(body, sec) {
		return true
	}
	for _, v := range fr.Headers {
		if bytes.Contains([]byte(v), sec) {
			return true
		}
	}
	return false
}

// sanitizeRespHeaders drops a Location whose host fails the allowlist (so the agent
// can't mechanically follow a credentialed redirect off-allowlist), then runs the
// reflect-guard over all headers.
func sanitizeRespHeaders(h http.Header, c *Credential, needles [][]byte) map[string][]string {
	out := http.Header{}
	for k, vs := range h {
		out[k] = append([]string(nil), vs...)
	}
	if loc := out.Get("Location"); loc != "" {
		if lu, err := url.Parse(loc); err != nil {
			out.Del("Location")
		} else if lh, err := normalizeHost(lu.Hostname()); err != nil || !hostAllowed(lh, c.AllowHosts) {
			out.Del("Location")
		}
	}
	reflectGuardHeaders(out, needles)
	return out
}

func readCapped(r io.Reader, max int64) ([]byte, bool) {
	buf, _ := io.ReadAll(io.LimitReader(r, max+1))
	if int64(len(buf)) > max {
		return buf[:max], true
	}
	return buf, false
}
