package server

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/lexxx233/joyvend-secretvault/internal/vault"
)

func newServer(t *testing.T, opt Options) *Server {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vault.json.enc")
	st, err := vault.Create(path, []byte("pw"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return New(st, opt)
}

// do issues a request and returns the recorder. remote sets RemoteAddr.
func do(h http.Handler, method, path, token, remote, body string) *httptest.ResponseRecorder {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, bytes.NewReader([]byte(body)))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	if token != "" {
		r.Header.Set("X-Vault-Token", token)
	}
	r.RemoteAddr = remote
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestRootAndHealthAndNotFound(t *testing.T) {
	s := newServer(t, Options{})
	h := s.Handler()
	if w := do(h, "GET", "/", "", "127.0.0.1:1", ""); w.Code != 200 {
		t.Fatalf("GET / => %d, want 200", w.Code)
	}
	w := do(h, "GET", "/healthz", "", "127.0.0.1:1", "")
	if w.Code != 200 {
		t.Fatalf("GET /healthz => %d, want 200", w.Code)
	}
	// health must not leak either token
	if bytes.Contains(w.Body.Bytes(), []byte(s.ControlToken())) || bytes.Contains(w.Body.Bytes(), []byte(s.UseToken())) {
		t.Fatal("health response leaked a token")
	}
	if w := do(h, "GET", "/nope", "", "127.0.0.1:1", ""); w.Code != 404 {
		t.Fatalf("GET /nope => %d, want 404", w.Code)
	}
}

func TestGuideEndpoint(t *testing.T) {
	s := newServer(t, Options{})
	h := s.Handler()
	if w := do(h, "GET", "/v1/vault/guide", "", "127.0.0.1:1", ""); w.Code != 401 {
		t.Fatalf("guide without token => %d, want 401", w.Code)
	}
	w := do(h, "GET", "/v1/vault/guide", s.UseToken(), "127.0.0.1:1", "")
	if w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte("by reference")) {
		t.Fatalf("guide => %d %q", w.Code, w.Body.String())
	}
}

func TestSnippetText(t *testing.T) {
	sn := SnippetText("http://127.0.0.1:8770", "TOK123")
	if !bytes.Contains([]byte(sn), []byte("TOK123")) || !bytes.Contains([]byte(sn), []byte("/v1/vault/guide")) {
		t.Fatalf("snippet missing token or guide pointer: %q", sn)
	}
}

func TestControlPlaneRejectsNonLoopback(t *testing.T) {
	s := newServer(t, Options{})
	h := s.Handler()
	w := do(h, "GET", "/api/vault/credentials", s.ControlToken(), "203.0.113.9:5000", "")
	if w.Code != 403 {
		t.Fatalf("non-loopback control => %d, want 403", w.Code)
	}
}

func TestControlPlaneRequiresControlToken(t *testing.T) {
	s := newServer(t, Options{})
	h := s.Handler()
	if w := do(h, "GET", "/api/vault/credentials", "", "127.0.0.1:5000", ""); w.Code != 401 {
		t.Fatalf("no token => %d, want 401", w.Code)
	}
	if w := do(h, "GET", "/api/vault/credentials", "wrong", "127.0.0.1:5000", ""); w.Code != 401 {
		t.Fatalf("wrong token => %d, want 401", w.Code)
	}
}

// The plane-separation proof: the agent's use token must NOT open the control plane.
func TestAgentTokenCannotReachControlPlane(t *testing.T) {
	s := newServer(t, Options{})
	h := s.Handler()
	body := `{"name":"x","type":"bearer","secret":"abcdef123","allow_hosts":["api.x.com"]}`
	w := do(h, "POST", "/api/vault/credentials", s.UseToken(), "127.0.0.1:5000", body)
	if w.Code != 401 {
		t.Fatalf("use token on control plane => %d, want 401", w.Code)
	}
}

func TestUsePlaneLoopbackByDefault(t *testing.T) {
	s := newServer(t, Options{}) // EnableLAN false
	h := s.Handler()
	w := do(h, "GET", "/v1/vault/credentials", s.UseToken(), "203.0.113.9:5000", "")
	if w.Code != 403 {
		t.Fatalf("non-loopback use (LAN off) => %d, want 403", w.Code)
	}
}

func TestUsePlaneLANAllowsNonLoopbackWithToken(t *testing.T) {
	s := newServer(t, Options{EnableLAN: true})
	h := s.Handler()
	// non-loopback + valid use token → allowed through to the handler
	if w := do(h, "GET", "/v1/vault/credentials", s.UseToken(), "203.0.113.9:5000", ""); w.Code != 200 {
		t.Fatalf("LAN use with token => %d, want 200", w.Code)
	}
	// but still requires the token
	if w := do(h, "GET", "/v1/vault/credentials", "nope", "203.0.113.9:5000", ""); w.Code != 401 {
		t.Fatalf("LAN use without token => %d, want 401", w.Code)
	}
}

func TestPutEnableFetchEndToEnd(t *testing.T) {
	// Upstream the agent will reach by reference.
	var gotAuth string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Write([]byte("ok"))
	}))
	defer up.Close()

	s := newServer(t, Options{})
	s.Engine().SetEgressDenyForTest(func(net.IP, bool) bool { return false }) // allow loopback upstream
	h := s.Handler()
	ctl, use := s.ControlToken(), s.UseToken()

	// create credential (control plane)
	put := `{"name":"api","type":"bearer","secret":"supersecretvalue","allow_hosts":["127.0.0.1"],"allow_insecure":true,"read_tier":"auto"}`
	if w := do(h, "POST", "/api/vault/credentials", ctl, "127.0.0.1:1", put); w.Code != 200 {
		t.Fatalf("put => %d %s", w.Code, w.Body.String())
	}
	// enable for session (control plane)
	if w := do(h, "POST", "/api/vault/credentials/api/enable", ctl, "127.0.0.1:1", `{"on":true}`); w.Code != 200 {
		t.Fatalf("enable => %d", w.Code)
	}
	// fetch by reference (use plane)
	fr := `{"credential":"api","method":"GET","url":"` + up.URL + `/x"}`
	w := do(h, "POST", "/v1/vault/fetch", use, "127.0.0.1:1", fr)
	if w.Code != 200 {
		t.Fatalf("fetch => %d %s", w.Code, w.Body.String())
	}
	var resp vault.FetchResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Body != "ok" {
		t.Fatalf("fetch body = %q", resp.Body)
	}
	if gotAuth != "Bearer supersecretvalue" {
		t.Fatalf("upstream auth = %q", gotAuth)
	}
	// the secret never appears in the agent-facing response
	if bytes.Contains(w.Body.Bytes(), []byte("supersecretvalue")) {
		t.Fatal("secret leaked into fetch response")
	}
}

func TestApprovalFlowEndToEnd(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(201) }))
	defer up.Close()

	s := newServer(t, Options{ApprovalTimeout: 2 * time.Second})
	s.Engine().SetEgressDenyForTest(func(net.IP, bool) bool { return false })
	h := s.Handler()
	ctl, use := s.ControlToken(), s.UseToken()

	put := `{"name":"api","type":"bearer","secret":"supersecretvalue","allow_hosts":["127.0.0.1"],"allow_insecure":true,"write_tier":"confirm"}`
	do(h, "POST", "/api/vault/credentials", ctl, "127.0.0.1:1", put)
	do(h, "POST", "/api/vault/credentials/api/enable", ctl, "127.0.0.1:1", `{"on":true}`)

	// Start a write that will block on approval.
	done := make(chan int, 1)
	go func() {
		fr := `{"credential":"api","method":"POST","url":"` + up.URL + `/"}`
		w := do(h, "POST", "/v1/vault/fetch", use, "127.0.0.1:1", fr)
		done <- w.Code
	}()

	// Poll pending, then approve via the control plane.
	var id string
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && id == "" {
		w := do(h, "GET", "/api/vault/approvals", ctl, "127.0.0.1:1", "")
		var got struct {
			Pending []pendingReq `json:"pending"`
		}
		json.Unmarshal(w.Body.Bytes(), &got)
		if len(got.Pending) == 1 {
			id = got.Pending[0].ID
		}
		time.Sleep(20 * time.Millisecond)
	}
	if id == "" {
		t.Fatal("no pending approval appeared")
	}
	// Agent must NOT be able to approve (use token on control plane → 401).
	if w := do(h, "POST", "/api/vault/approvals/"+id+"/decide", use, "127.0.0.1:1", `{"approve":true}`); w.Code != 401 {
		t.Fatalf("agent self-approve => %d, want 401", w.Code)
	}
	// Human approves.
	if w := do(h, "POST", "/api/vault/approvals/"+id+"/decide", ctl, "127.0.0.1:1", `{"approve":true}`); w.Code != 200 {
		t.Fatalf("approve => %d", w.Code)
	}
	if code := <-done; code != 200 {
		t.Fatalf("approved write fetch => %d", code)
	}
}
