package component_test

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"mykeep.ai/vault/component"
	"mykeep.ai/vault/internal/secret"
)

func newDEK(t *testing.T) []byte {
	t.Helper()
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatal(err)
	}
	return dek
}

// loopback request with a vault token header (both planes require loopback).
func vreq(method, path, token, body string) *http.Request {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	r.RemoteAddr = "127.0.0.1:54321"
	r.Host = "127.0.0.1:8765"
	if token != "" {
		r.Header.Set("X-Vault-Token", token)
	}
	return r
}

const (
	useTok  = "use-token-for-tests"
	ctrlTok = "control-token-for-tests"
	secVal  = "sk_test_SUPERSECRET_should_never_leak"
)

func newComponent(t *testing.T, dir string, dek []byte) *component.Component {
	t.Helper()
	c, err := component.New(component.Options{
		DataDir: dir, Version: "test", UseToken: useTok, ControlToken: ctrlTok,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Unlock(context.Background(), dek); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	return c
}

// TestComponentInjectedDEKRoundTrip proves vault can be unlocked with an injected key,
// serves both planes on a shared mux, a credential added on the control plane is
// listed (secret-free) on the use plane, and the data survives Lock + reopen.
func TestComponentInjectedDEKRoundTrip(t *testing.T) {
	dir := t.TempDir()
	dek := newDEK(t)

	c := newComponent(t, dir, dek)
	mux := http.NewServeMux()
	c.Mount(mux)

	// control plane: add a credential (loopback + control token).
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, vreq("POST", "/api/vault/credentials", ctrlTok,
		`{"name":"stripe","type":"bearer","secret":"`+secVal+`","allow_hosts":["api.stripe.com"]}`))
	if w.Code != 200 {
		t.Fatalf("put credential => %d %s", w.Code, w.Body.String())
	}

	// use plane: list credentials (loopback + use token) — name present, secret absent.
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, vreq("GET", "/v1/vault/credentials", useTok, ""))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "stripe") {
		t.Fatalf("use-plane list => %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), secVal) {
		t.Fatal("secret leaked on the use plane")
	}

	// control plane must reject the agent's use token (plane separation).
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, vreq("GET", "/api/vault/credentials", useTok, ""))
	if w.Code != 401 {
		t.Fatalf("control plane with use token => %d, want 401", w.Code)
	}

	if err := c.Lock(); err != nil {
		t.Fatalf("lock: %v", err)
	}

	// reopen with the SAME key — credential persists.
	c2 := newComponent(t, dir, dek)
	defer c2.Lock()
	mux2 := http.NewServeMux()
	c2.Mount(mux2)
	w = httptest.NewRecorder()
	mux2.ServeHTTP(w, vreq("GET", "/v1/vault/credentials", useTok, ""))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "stripe") {
		t.Fatalf("after reopen => %d %s", w.Code, w.Body.String())
	}
}

// TestComponentWrongDEKFails proves the headerless store is genuinely keyed by the DEK.
func TestComponentWrongDEKFails(t *testing.T) {
	dir := t.TempDir()
	dek := newDEK(t)
	c := newComponent(t, dir, dek)
	if err := c.Lock(); err != nil {
		t.Fatalf("lock: %v", err)
	}

	c2, _ := component.New(component.Options{DataDir: dir, Version: "test"})
	if err := c2.Unlock(context.Background(), newDEK(t)); err == nil {
		_ = c2.Lock()
		t.Fatal("expected unlock with a wrong DEK to fail")
	}
}

// TestOpenSealedRejectsStandaloneFile proves a standalone (JVS1, password-keyed) file
// surfaces a clear error in suite mode rather than an opaque GCM failure.
func TestOpenSealedRejectsStandaloneFile(t *testing.T) {
	legacy := append([]byte("JVS1"), make([]byte, 96)...) // magic + filler
	if _, _, err := secret.OpenSealed(make([]byte, 32), legacy); !errors.Is(err, secret.ErrStandaloneFile) {
		t.Fatalf("want ErrStandaloneFile, got %v", err)
	}
}
