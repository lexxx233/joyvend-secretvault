package vault

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func gzipBytes(b []byte) []byte {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	_, _ = gw.Write(b)
	_ = gw.Close()
	return buf.Bytes()
}

// TestReflectGuardCatchesGzipReflectedSecret: an agent that sets Accept-Encoding: gzip
// must NOT be able to smuggle the secret out via a compressed reflecting response — the
// agent header is stripped so Go decompresses and the reflect-guard scans plaintext.
func TestReflectGuardCatchesGzipReflectedSecret(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// reflect the injected Authorization (which carries the secret), gzipped
		body := gzipBytes([]byte(`{"echo":"` + r.Header.Get("Authorization") + `"}`))
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	e, _ := fetchFixture(t, true)

	resp, ferr := e.Fetch(context.Background(), "x", FetchRequest{
		Credential: "api", Method: "GET", URL: srv.URL + "/",
		Headers: map[string]string{"Accept-Encoding": "gzip"}, // the agent tries to force compression
	})
	if ferr == nil || ferr.Code != errReflect.Code {
		t.Fatalf("gzip-reflected secret => resp=%q ferr=%v, want reflect_blocked", resp.Body, ferr)
	}
}

// TestNonIdentityEncodingFailsClosed: a response in an encoding the guard cannot read is
// rejected — the agent must never receive an unscannable (possibly secret-bearing) body.
func TestNonIdentityEncodingFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "br") // Go didn't request br → not decoded
		_, _ = w.Write([]byte("opaque-bytes-the-guard-cannot-scan"))
	}))
	defer srv.Close()
	e, _ := fetchFixture(t, true)
	_, ferr := e.Fetch(context.Background(), "x", FetchRequest{Credential: "api", Method: "GET", URL: srv.URL + "/"})
	if ferr == nil || ferr.Code != errReflect.Code {
		t.Fatalf("br-encoded response => %v, want reflect_blocked (fail closed)", ferr)
	}
}

// TestBenignGzipResponseStillWorks: a normal gzip response that does not reflect the
// secret is transparently decompressed and returned to the agent.
func TestBenignGzipResponseStillWorks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(gzipBytes([]byte("plain hello, no secret here")))
	}))
	defer srv.Close()
	e, _ := fetchFixture(t, true)
	resp, ferr := e.Fetch(context.Background(), "x", FetchRequest{Credential: "api", Method: "GET", URL: srv.URL + "/"})
	if ferr != nil {
		t.Fatalf("benign gzip => %v", ferr)
	}
	if resp.Body != "plain hello, no secret here" {
		t.Fatalf("body not transparently decompressed: %q", resp.Body)
	}
}

// TestPortRestriction: a private-egress (allow_private) credential is restricted to the
// scheme's standard port, so the agent can't reach internal services on other ports.
func TestPortRestriction(t *testing.T) {
	e, store := fetchFixture(t, true)
	_ = store.Put("api", &Credential{
		Type: AuthBearer, Secret: testSecret, AllowHosts: []string{"127.0.0.1"},
		AllowInsecure: true, AllowPriv: true, ReadTier: TierAuto, WriteTier: TierConfirm,
	})
	_ = store.Enable("api", true)
	for _, u := range []string{"http://127.0.0.1:22/", "https://127.0.0.1:6379/", "http://127.0.0.1:8080/"} {
		_, ferr := e.Fetch(context.Background(), "x", FetchRequest{Credential: "api", Method: "GET", URL: u})
		if ferr == nil || ferr.Code != errBadURL.Code {
			t.Fatalf("non-standard port %s on a private cred => %v, want bad_url", u, ferr)
		}
	}
}
