package gui

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func newApp(t *testing.T) *App {
	return New(filepath.Join(t.TempDir(), "vault.json.enc"), "127.0.0.1:0", 0)
}

// req builds a loopback request. lt (launch token) and cookie are optional.
func req(h http.Handler, method, path, lt, cookie, body string) *httptest.ResponseRecorder {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	r.RemoteAddr = "127.0.0.1:5000"
	if lt != "" {
		r.Header.Set("X-Launch-Token", lt)
	}
	if cookie != "" {
		r.Header.Set("Cookie", cookie)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func sessionFrom(w *httptest.ResponseRecorder) string {
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			return sessionCookie + "=" + c.Value
		}
	}
	return ""
}

func TestGUIServesIndex(t *testing.T) {
	w := req(newApp(t).handler(), "GET", "/", "", "", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Vault") {
		t.Fatalf("index => %d, has Vault=%v", w.Code, strings.Contains(w.Body.String(), "Vault"))
	}
}

func TestGUIUnlockSessionFlow(t *testing.T) {
	a := newApp(t)
	h := a.handler()
	lt := a.launchToken

	if w := req(h, "GET", "/api/state", "", "", ""); !strings.Contains(w.Body.String(), `"first_launch":true`) {
		t.Fatalf("state => %s", w.Body.String())
	}
	if w := req(h, "POST", "/api/vault/credentials", "", "", `{}`); w.Code != 423 {
		t.Fatalf("locked control => %d, want 423", w.Code)
	}
	// setup (with the launch token) unlocks + sets a session cookie + returns a use token
	w := req(h, "POST", "/api/setup", lt, "", `{"password":"hunter2"}`)
	if w.Code != 200 {
		t.Fatalf("setup => %d %s", w.Code, w.Body.String())
	}
	cookie := sessionFrom(w)
	if cookie == "" {
		t.Fatal("no session cookie set on unlock")
	}
	if !strings.Contains(w.Body.String(), "use_token") {
		t.Fatal("setup did not return a use token")
	}

	body := `{"name":"gh","type":"bearer","secret":"abcdef123456","allow_hosts":["api.github.com"]}`
	if w := req(h, "POST", "/api/vault/credentials", "", cookie, body); w.Code != 200 {
		t.Fatalf("add with session => %d %s", w.Code, w.Body.String())
	}
	if w := req(h, "POST", "/api/vault/credentials", "", "", body); w.Code != 401 {
		t.Fatalf("add without session => %d, want 401 (plane separation)", w.Code)
	}
	lw := req(h, "GET", "/api/vault/credentials", "", cookie, "")
	if !strings.Contains(lw.Body.String(), "gh") || strings.Contains(lw.Body.String(), "abcdef123456") {
		t.Fatalf("list leaked or missing: %s", lw.Body.String())
	}
}

// TestGUISetupUnlockRequireLaunchToken: a co-resident process without the launch token
// cannot set the master password or unlock (defeats the first-launch setup-capture).
func TestGUISetupUnlockRequireLaunchToken(t *testing.T) {
	h := newApp(t).handler()
	if w := req(h, "POST", "/api/setup", "", "", `{"password":"x"}`); w.Code != 401 {
		t.Fatalf("setup without launch token => %d, want 401", w.Code)
	}
	if w := req(h, "POST", "/api/unlock", "", "", `{"password":"x"}`); w.Code != 401 {
		t.Fatalf("unlock without launch token => %d, want 401", w.Code)
	}
}

// TestGUILockRequiresSession: /api/lock is not an unauthenticated loopback DoS.
func TestGUILockRequiresSession(t *testing.T) {
	a := newApp(t)
	h := a.handler()
	req(h, "POST", "/api/setup", a.launchToken, "", `{"password":"pw"}`) // unlock
	if w := req(h, "POST", "/api/lock", "", "", ""); w.Code != 401 {
		t.Fatalf("lock without session => %d, want 401", w.Code)
	}
	if w := req(h, "GET", "/api/state", "", "", ""); !strings.Contains(w.Body.String(), `"unlocked":true`) {
		t.Fatalf("vault should still be unlocked: %s", w.Body.String())
	}
}

// TestGUIStateTokenGatedBySession: the agent token is handed only to the human's session.
func TestGUIStateTokenGatedBySession(t *testing.T) {
	a := newApp(t)
	h := a.handler()
	w := req(h, "POST", "/api/setup", a.launchToken, "", `{"password":"pw"}`)
	cookie := sessionFrom(w)
	if w := req(h, "GET", "/api/state", "", "", ""); !strings.Contains(w.Body.String(), `"use_token":""`) {
		t.Fatalf("state without session leaked a token: %s", w.Body.String())
	}
	if w := req(h, "GET", "/api/state", "", cookie, ""); strings.Contains(w.Body.String(), `"use_token":""`) {
		t.Fatalf("state with session should include the token: %s", w.Body.String())
	}
}

func TestGUIWrongPassword(t *testing.T) {
	a := newApp(t)
	h := a.handler()
	w := req(h, "POST", "/api/setup", a.launchToken, "", `{"password":"right"}`)
	cookie := sessionFrom(w)
	req(h, "POST", "/api/lock", "", cookie, "") // lock with the session
	if w := req(h, "POST", "/api/unlock", a.launchToken, "", `{"password":"wrong"}`); w.Code != 401 {
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
