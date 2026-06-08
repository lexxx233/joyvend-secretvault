package vault

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/url"
)

// secretNeedles expands each injected wire value into the encodings a hostile or
// honest upstream might echo it in: raw, base64 (std+url), hex, percent-encoded.
// This is DEFENSE-IN-DEPTH against echo, not a guarantee (SECURITY.md).
func secretNeedles(injected [][]byte) [][]byte {
	var out [][]byte
	seen := map[string]bool{}
	add := func(b []byte) {
		if len(b) < 6 { // too short to scan meaningfully without false positives
			return
		}
		if !seen[string(b)] {
			seen[string(b)] = true
			out = append(out, b)
		}
	}
	for _, v := range injected {
		if len(v) == 0 {
			continue
		}
		add(v)
		add([]byte(base64.StdEncoding.EncodeToString(v)))
		add([]byte(base64.RawStdEncoding.EncodeToString(v)))
		add([]byte(base64.URLEncoding.EncodeToString(v)))
		add([]byte(base64.RawURLEncoding.EncodeToString(v)))
		add([]byte(hex.EncodeToString(v)))
		add([]byte(url.QueryEscape(string(v))))
	}
	return out
}

func containsAny(data []byte, needles [][]byte) bool {
	for _, n := range needles {
		if bytes.Contains(data, n) {
			return true
		}
	}
	return false
}

// reflectGuardHeaders drops any response header whose value echoes the injected
// secret (in any scanned encoding). Returns the count dropped.
func reflectGuardHeaders(h http.Header, needles [][]byte) int {
	dropped := 0
	for k, vs := range h {
		for _, v := range vs {
			if containsAny([]byte(v), needles) {
				h.Del(k)
				dropped++
				break
			}
		}
	}
	return dropped
}
