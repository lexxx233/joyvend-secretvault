package vault

import (
	"encoding/base64"
	"net/http"
	"strings"
)

// denylistHeaders are never accepted from the agent — they are auth/identity headers
// the agent must not control (red-team: strip-then-inject).
var denylistHeaders = map[string]bool{
	"authorization":       true,
	"proxy-authorization": true,
	"cookie":              true,
	"host":                true,
	"content-length":      true,
	// accept-encoding is stripped so the agent cannot force a COMPRESSED response that
	// the reflect-guard (which scans raw bytes) can't read — Go's transport then
	// negotiates gzip itself and transparently decompresses before the scan.
	"accept-encoding": true,
}

// buildHeaders constructs the outgoing header set from scratch: agent-supplied
// headers are copied via http.Header.Set (which canonicalises and rejects CRLF),
// minus the denylist and the credential's own injection header. The authoritative
// auth value is written LAST by injectAuth, so agent input can never override it.
func buildHeaders(agent map[string]string, injectName string) (http.Header, error) {
	h := http.Header{}
	inj := strings.ToLower(strings.TrimSpace(injectName))
	for k, v := range agent {
		lk := strings.ToLower(strings.TrimSpace(k))
		if denylistHeaders[lk] || lk == inj {
			continue
		}
		if !validHeaderField(k) || !validHeaderValue(v) {
			return nil, errBadHeader
		}
		h.Set(k, v)
	}
	return h, nil
}

// injectAuth writes the credential's auth onto the request (last word) and returns
// the secret-bearing wire value(s) for the reflect-guard to scan responses against.
func injectAuth(c *Credential, h http.Header) [][]byte {
	switch c.Type {
	case AuthBearer:
		val := "Bearer " + c.Secret
		h.Set("Authorization", val)
		return [][]byte{[]byte(c.Secret), []byte(val)}
	case AuthHeader:
		h.Set(c.HeaderName, c.Secret)
		return [][]byte{[]byte(c.Secret)}
	case AuthBasic:
		token := base64.StdEncoding.EncodeToString([]byte(c.Username + ":" + c.Secret))
		h.Set("Authorization", "Basic "+token)
		return [][]byte{[]byte(c.Secret), []byte(token)}
	case AuthCustom:
		val := strings.ReplaceAll(c.Template, "${secret}", c.Secret)
		h.Set("Authorization", val)
		return [][]byte{[]byte(c.Secret), []byte(val)}
	}
	return nil
}

// injectHeaderName is the header a credential injects (used to strip an agent attempt
// to set the same one).
func injectHeaderName(c *Credential) string {
	switch c.Type {
	case AuthHeader:
		return c.HeaderName
	default:
		return "Authorization"
	}
}

// validHeaderField/validHeaderValue reject control chars / CRLF (header splitting).
func validHeaderField(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= ' ' || c == ':' || c >= 0x7f {
			return false
		}
	}
	return true
}

func validHeaderValue(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\r' || c == '\n' || c == 0 {
			return false
		}
	}
	return true
}
