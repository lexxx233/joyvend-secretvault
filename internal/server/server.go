// Package server exposes SecretVault over HTTP as two planes (DESIGN.md §2):
//   - the USE plane (/v1/vault) the agent calls — fetch + metadata list — guarded by
//     a mandatory token, loopback-only unless LAN mode is explicitly enabled;
//   - the CONTROL plane (/api/vault) the human GUI calls — credential CRUD, enable,
//     approvals, audit — ALWAYS loopback-only and gated by a separate control token.
//
// The split is the load-bearing security control: the agent can never create, read,
// enable, or self-approve a credential (SECURITY.md §2).
package server

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/lexxx233/joyvend-secretvault/internal/vault"
)

// Options configures a Server. Tokens are generated if empty.
type Options struct {
	EnableLAN       bool          // expose the USE plane on the LAN (control plane stays loopback)
	UseToken        string        // agent token for /v1/vault
	ControlToken    string        // GUI/CLI token for /api/vault (X-Vault-Token)
	ControlSession  string        // GUI session-cookie value also accepted on the control plane
	ApprovalTimeout time.Duration // how long a write blocks for a human (default 2m)
}

// Server is the HTTP front for a vault Store.
type Server struct {
	store    *vault.Store
	engine   *vault.Engine
	approver *pendingApprover
	opt      Options
}

// New builds a Server over an unlocked store.
func New(store *vault.Store, opt Options) *Server {
	if opt.UseToken == "" {
		opt.UseToken = randToken()
	}
	if opt.ControlToken == "" {
		opt.ControlToken = randToken()
	}
	if opt.ApprovalTimeout <= 0 {
		opt.ApprovalTimeout = 2 * time.Minute
	}
	ap := newPendingApprover(opt.ApprovalTimeout)
	return &Server{
		store:    store,
		engine:   vault.NewEngine(store, ap),
		approver: ap,
		opt:      opt,
	}
}

// UseToken / ControlToken expose the minted tokens (shown by the GUI/TTY at launch).
func (s *Server) UseToken() string     { return s.opt.UseToken }
func (s *Server) ControlToken() string { return s.opt.ControlToken }

// Engine exposes the underlying engine (used by tests to override egress policy).
func (s *Server) Engine() *vault.Engine { return s.engine }

// Handler returns the composed HTTP handler for headless `serve` mode (root + health
// + both planes).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.handleRoot)
	mux.HandleFunc("GET /healthz", s.handleHealth)
	s.mountPlanes(mux)
	return mux
}

// PlanesHandler returns just the two vault planes (no root/health) — used by the GUI,
// which serves its own dashboard at /.
func (s *Server) PlanesHandler() http.Handler {
	mux := http.NewServeMux()
	s.mountPlanes(mux)
	return mux
}

func (s *Server) mountPlanes(mux *http.ServeMux) {
	// USE plane: loopback-only unless LAN enabled; always requires the use token.
	use := http.NewServeMux()
	use.HandleFunc("POST /v1/vault/fetch", s.handleFetch)
	use.HandleFunc("GET /v1/vault/credentials", s.handleList)
	use.HandleFunc("GET /v1/vault/guide", s.handleGuide)
	useGuard := s.requireToken(s.opt.UseToken, use)
	if !s.opt.EnableLAN {
		useGuard = loopbackOnly(useGuard)
	}
	mux.Handle("/v1/vault/", useGuard)

	// CONTROL plane: ALWAYS loopback-only; accepts the control token OR the GUI session.
	ctrl := http.NewServeMux()
	ctrl.HandleFunc("POST /api/vault/credentials", s.handlePut)
	ctrl.HandleFunc("GET /api/vault/credentials", s.handleList)
	ctrl.HandleFunc("DELETE /api/vault/credentials/{name}", s.handleDelete)
	ctrl.HandleFunc("POST /api/vault/credentials/{name}/enable", s.handleEnable)
	ctrl.HandleFunc("GET /api/vault/audit", s.handleAudit)
	ctrl.HandleFunc("GET /api/vault/audit/verify", s.handleAuditVerify)
	ctrl.HandleFunc("GET /api/vault/approvals", s.handlePending)
	ctrl.HandleFunc("POST /api/vault/approvals/{id}/decide", s.handleDecide)
	mux.Handle("/api/vault/", loopbackOnly(s.controlAuth(ctrl)))
}

// --- root / health (no auth, no secrets) ---

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"ok":      true,
		"service": "secretvault",
		"planes":  []string{"/v1/vault (agent)", "/api/vault (control, loopback-only)"},
		"lan":     s.opt.EnableLAN,
	})
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(rootHTML))
}

const rootHTML = `<!doctype html><html><head><meta charset="utf-8">
<title>SecretVault</title><style>
body{font-family:system-ui,sans-serif;max-width:42rem;margin:4rem auto;padding:0 1rem;line-height:1.6;color:#1c2833}
code{background:#eef;padding:.1em .35em;border-radius:3px}h1{margin-bottom:.2em}.muted{color:#667}
</style></head><body>
<h1>🔐 SecretVault</h1>
<p class="muted">Running. This is a local <strong>API</strong>, not a web app — there is no GUI yet,
so visiting a path in the browser will 404. That's expected.</p>
<ul>
<li><code>POST /v1/vault/fetch</code> — the agent acts by reference (needs the <em>use</em> token).</li>
<li><code>GET&nbsp; /v1/vault/credentials</code> — credential metadata (no secrets).</li>
<li><code>/api/vault/*</code> — credential create/enable/approve/audit (loopback-only, <em>control</em> token).</li>
<li><code>GET&nbsp; /healthz</code> — JSON status.</li>
</ul>
<p class="muted">Both tokens were printed in the terminal at launch. Manage credentials with, e.g.:<br>
<code>curl -H "X-Vault-Token: $CONTROL_TOKEN" .../api/vault/credentials</code></p>
</body></html>`

// --- use plane handlers ---

func (s *Server) handleFetch(w http.ResponseWriter, r *http.Request) {
	var fr vault.FetchRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20)).Decode(&fr); err != nil {
		writeErr(w, 400, "bad_request")
		return
	}
	resp, ferr := s.engine.Fetch(r.Context(), r.RemoteAddr, fr)
	if ferr != nil {
		writeJSON(w, ferr.Status, map[string]any{"error": ferr.Code, "audit_id": resp.AuditID})
		return
	}
	writeJSON(w, 200, resp)
}

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"credentials": s.store.List()})
}

// --- control plane handlers ---

type putRequest struct {
	Name string `json:"name"`
	vault.Credential
}

func (s *Server) handlePut(w http.ResponseWriter, r *http.Request) {
	var req putRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeErr(w, 400, "bad_request")
		return
	}
	c := req.Credential
	if err := s.store.Put(req.Name, &c); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	m, _ := s.store.Meta(req.Name)
	writeJSON(w, 200, m)
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Delete(r.PathValue("name")); err != nil {
		writeErr(w, 404, "not_found")
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": true})
}

func (s *Server) handleEnable(w http.ResponseWriter, r *http.Request) {
	var body struct {
		On bool `json:"on"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if err := s.store.Enable(r.PathValue("name"), body.On); err != nil {
		writeErr(w, 404, "not_found")
		return
	}
	writeJSON(w, 200, map[string]any{"enabled": body.On})
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"audit": s.store.Audit()})
}

func (s *Server) handleAuditVerify(w http.ResponseWriter, r *http.Request) {
	if err := s.store.VerifyAudit(); err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handlePending(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"pending": s.approver.list()})
}

func (s *Server) handleDecide(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Approve bool `json:"approve"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if !s.approver.decide(r.PathValue("id"), body.Approve) {
		writeErr(w, 404, "no_such_pending")
		return
	}
	writeJSON(w, 200, map[string]any{"decided": true})
}

// --- middleware ---

func (s *Server) requireToken(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !tokenOK(r.Header.Get("X-Vault-Token"), token) {
			writeErr(w, 401, "unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// controlAuth gates the control plane: the X-Vault-Token control token (CLI/curl) OR
// the GUI session cookie (set after a password unlock). A co-resident agent has
// neither — it never sees the control token and cannot unlock to mint a session.
func (s *Server) controlAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if tokenOK(r.Header.Get("X-Vault-Token"), s.opt.ControlToken) {
			next.ServeHTTP(w, r)
			return
		}
		if s.opt.ControlSession != "" {
			if c, err := r.Cookie("sv_session"); err == nil && tokenOK(c.Value, s.opt.ControlSession) {
				next.ServeHTTP(w, r)
				return
			}
		}
		writeErr(w, 401, "unauthorized")
	})
}

func tokenOK(got, want string) bool {
	return want != "" && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func loopbackOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			writeErr(w, 403, "loopback_only")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// --- helpers ---

func randToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	// Never echo upstream/raw detail; msg is always a fixed code or validation string.
	writeJSON(w, code, map[string]any{"error": strings.SplitN(msg, "\n", 2)[0]})
}
