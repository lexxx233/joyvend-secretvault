package gui

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func newApp(t *testing.T) *App {
	return New(filepath.Join(t.TempDir(), "vault.json.enc"), "127.0.0.1:0")
}

func req(h http.Handler, method, path, cookie, body string) *httptest.ResponseRecorder {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	r.RemoteAddr = "127.0.0.1:5000"
	if cookie != "" {
		r.Header.Set("Cookie", cookie)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func sessionCookie(w *httptest.ResponseRecorder) string {
	for _, c := range w.Result().Cookies() {
		if c.Name == "sv_session" && c.Value != "" {
			return "sv_session=" + c.Value
		}
	}
	return ""
}

func TestGUIServesIndex(t *testing.T) {
	w := req(newApp(t).handler(), "GET", "/", "", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "SecretVault") {
		t.Fatalf("index => %d, has SecretVault=%v", w.Code, strings.Contains(w.Body.String(), "SecretVault"))
	}
}

func TestGUIUnlockSessionFlow(t *testing.T) {
	a := newApp(t)
	h := a.handler()

	// first launch
	if w := req(h, "GET", "/api/state", "", ""); !strings.Contains(w.Body.String(), `"first_launch":true`) {
		t.Fatalf("state => %s", w.Body.String())
	}
	// control plane is locked before unlock
	if w := req(h, "POST", "/api/vault/credentials", "", `{}`); w.Code != 423 {
		t.Fatalf("locked control => %d, want 423", w.Code)
	}
	// setup creates + unlocks + sets a session cookie + returns a use token
	w := req(h, "POST", "/api/setup", "", `{"password":"hunter2"}`)
	if w.Code != 200 {
		t.Fatalf("setup => %d %s", w.Code, w.Body.String())
	}
	cookie := sessionCookie(w)
	if cookie == "" {
		t.Fatal("no session cookie set on unlock")
	}
	if !strings.Contains(w.Body.String(), "use_token") {
		t.Fatal("setup did not return a use token")
	}

	body := `{"name":"gh","type":"bearer","secret":"abcdef123456","allow_hosts":["api.github.com"]}`
	// with the session cookie the human can add a credential
	if w := req(h, "POST", "/api/vault/credentials", cookie, body); w.Code != 200 {
		t.Fatalf("add with session => %d %s", w.Code, w.Body.String())
	}
	// WITHOUT the cookie (a co-resident agent) the control plane is closed
	if w := req(h, "POST", "/api/vault/credentials", "", body); w.Code != 401 {
		t.Fatalf("add without session => %d, want 401 (plane separation)", w.Code)
	}
	// list reflects the credential, with no secret
	lw := req(h, "GET", "/api/vault/credentials", cookie, "")
	if !strings.Contains(lw.Body.String(), "gh") || strings.Contains(lw.Body.String(), "abcdef123456") {
		t.Fatalf("list leaked or missing: %s", lw.Body.String())
	}
}

func TestGUIWrongPassword(t *testing.T) {
	a := newApp(t)
	h := a.handler()
	req(h, "POST", "/api/setup", "", `{"password":"right"}`)
	// lock, then unlock with the wrong password
	req(h, "POST", "/api/lock", "", "")
	if w := req(h, "POST", "/api/unlock", "", `{"password":"wrong"}`); w.Code != 401 {
		t.Fatalf("wrong password => %d, want 401", w.Code)
	}
}

func TestGUILoopbackGuardRejectsRemote(t *testing.T) {
	h := loopbackGuard(newApp(t).handler())
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.4:9999"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("remote GUI access => %d, want 403", w.Code)
	}
}
