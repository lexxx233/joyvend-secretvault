package vault

import (
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"testing"
)

func TestSecretNeedlesCoversEncodings(t *testing.T) {
	secret := []byte("supersecretvalue")
	needles := secretNeedles([][]byte{secret})
	mustHave := [][]byte{
		secret,
		[]byte(base64.StdEncoding.EncodeToString(secret)),
		[]byte(hex.EncodeToString(secret)),
	}
	for _, m := range mustHave {
		if !containsAny(m, needles) {
			t.Errorf("needles missing encoding %q", m)
		}
	}
}

func TestReflectGuardDropsEchoedHeader(t *testing.T) {
	secret := []byte("tok_abcdef123456")
	needles := secretNeedles([][]byte{secret})
	h := http.Header{}
	h.Set("X-Ok", "fine")
	h.Set("X-Echo-Raw", "tok_abcdef123456")
	h.Set("X-Echo-B64", base64.StdEncoding.EncodeToString(secret))
	dropped := reflectGuardHeaders(h, needles)
	if dropped != 2 {
		t.Fatalf("dropped %d headers, want 2", dropped)
	}
	if h.Get("X-Echo-Raw") != "" || h.Get("X-Echo-B64") != "" {
		t.Fatal("echoed secret header survived")
	}
	if h.Get("X-Ok") != "fine" {
		t.Fatal("benign header dropped")
	}
}

func TestShortSecretsNotScanned(t *testing.T) {
	// Very short injected values would false-positive everywhere; they're skipped.
	needles := secretNeedles([][]byte{[]byte("ab")})
	if len(needles) != 0 {
		t.Fatalf("short secret produced needles: %v", needles)
	}
}
