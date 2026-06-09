// Package gui serves Vault's local web app: a loopback dashboard (opened in
// the browser) that unlocks the vault with a password, then lets the human add and
// manage credentials, approve writes, and read the audit log. Secret input IS the
// control plane (DESIGN.md §2), so it lives here, gated by a password-derived session
// the agent can never obtain. Pure Go, no toolkit, no CGo.
package gui

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"mykeep.ai/vault/internal/secret"
	"mykeep.ai/vault/internal/server"
	"mykeep.ai/vault/internal/vault"
)

const sessionCookie = "sv_session"

//go:embed web/index.html
var indexHTML []byte

// App owns the GUI lifecycle: locked until the human unlocks via the browser.
type App struct {
	vaultPath   string
	addr        string
	idle        time.Duration
	launchToken string // handed to the human's browser via the opened URL; required by setup/unlock

	mu       sync.Mutex
	store    *vault.Store
	srv      *server.Server
	planes   http.Handler
	session  string
	lastSeen time.Time
}

// New builds a GUI app over a vault file path. idle<=0 disables idle auto-lock.
func New(vaultPath, addr string, idle time.Duration) *App {
	return &App{vaultPath: vaultPath, addr: addr, idle: idle, launchToken: randHex(24)}
}

// Run serves the GUI and opens the browser, blocking until ctx is done.
func (a *App) Run(ctx context.Context) error {
	httpSrv := &http.Server{Addr: a.addr, Handler: loopbackGuard(a.touch(a.handler()))}
	errCh := make(chan error, 1)
	go func() {
		if e := httpSrv.ListenAndServe(); e != nil && e != http.ErrServerClosed {
			errCh <- e
		}
	}()
	url := "http://" + a.addr + "/?lt=" + a.launchToken
	fmt.Printf("\n🔐  Vault GUI: %s  (opening your browser…)\n", url)
	_ = openBrowser(url)

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = httpSrv.Shutdown(sctx)
			cancel()
			return a.lockNow()
		case e := <-errCh:
			_ = a.lockNow()
			return e
		case <-ticker.C:
			a.maybeIdleLock()
		}
	}
}

// lockNow seals the vault and zeroizes the key. Safe to call when locked.
func (a *App) lockNow() error {
	a.mu.Lock()
	st := a.store
	a.store, a.srv, a.planes, a.session = nil, nil, nil, ""
	a.mu.Unlock()
	if st != nil {
		return st.Close()
	}
	return nil
}

func (a *App) maybeIdleLock() {
	if a.idle <= 0 {
		return
	}
	a.mu.Lock()
	idle := a.srv != nil && time.Since(a.lastSeen) > a.idle
	a.mu.Unlock()
	if idle {
		fmt.Fprintln(os.Stderr, "idle auto-lock — sealing the vault")
		_ = a.lockNow()
	}
}

// touch resets the idle clock on HUMAN/control-plane activity only — not the agent's
// /v1/vault use-plane traffic (which must not hold the vault open past the human leaving).
func (a *App) touch(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/v1/") {
			a.mu.Lock()
			if a.srv != nil {
				a.lastSeen = time.Now()
			}
			a.mu.Unlock()
		}
		next.ServeHTTP(w, r)
	})
}

func (a *App) hasLaunchToken(r *http.Request) bool {
	got := r.Header.Get("X-Launch-Token")
	return got != "" && subtle.ConstantTimeCompare([]byte(got), []byte(a.launchToken)) == 1
}

func (a *App) hasSession(r *http.Request) bool {
	a.mu.Lock()
	sess := a.session
	a.mu.Unlock()
	if sess == "" {
		return false
	}
	c, err := r.Cookie(sessionCookie)
	return err == nil && subtle.ConstantTimeCompare([]byte(c.Value), []byte(sess)) == 1
}

func (a *App) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", a.index)
	mux.HandleFunc("GET /api/state", a.state)
	mux.HandleFunc("POST /api/setup", a.setup)
	mux.HandleFunc("POST /api/unlock", a.unlock)
	mux.HandleFunc("POST /api/lock", a.lock)
	mux.Handle("/v1/vault/", http.HandlerFunc(a.proxy))
	mux.Handle("/api/vault/", http.HandlerFunc(a.proxy))
	return mux
}

func (a *App) index(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Never cache the dashboard — otherwise a browser serves a stale build's UI
	// after the binary is updated.
	w.Header().Set("Cache-Control", "no-store, must-revalidate")
	_, _ = w.Write(indexHTML)
}

func (a *App) state(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	unlocked := a.srv != nil
	sess := a.session
	tok := ""
	if unlocked {
		tok = a.srv.UseToken()
	}
	a.mu.Unlock()
	useToken := ""
	if unlocked && sess != "" { // only the human's session sees the agent token
		if c, err := r.Cookie(sessionCookie); err == nil && subtle.ConstantTimeCompare([]byte(c.Value), []byte(sess)) == 1 {
			useToken = tok
		}
	}
	_, statErr := os.Stat(a.vaultPath)
	writeJSON(w, 200, map[string]any{
		"first_launch": os.IsNotExist(statErr),
		"unlocked":     unlocked,
		"use_token":    useToken,
	})
}

type passReq struct {
	Password string `json:"password"`
}

func (a *App) setup(w http.ResponseWriter, r *http.Request) {
	if !a.hasLaunchToken(r) { // only the human's launched browser may set the password
		writeErr(w, 401, "launch token required")
		return
	}
	if _, err := os.Stat(a.vaultPath); err == nil {
		writeErr(w, 409, "already set up")
		return
	}
	a.open(w, r, true)
}

func (a *App) unlock(w http.ResponseWriter, r *http.Request) {
	if !a.hasLaunchToken(r) {
		writeErr(w, 401, "launch token required")
		return
	}
	a.open(w, r, false)
}

func (a *App) open(w http.ResponseWriter, r *http.Request, create bool) {
	var req passReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Password == "" {
		writeErr(w, 400, "password required")
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.srv != nil {
		writeJSON(w, 200, map[string]any{"unlocked": true})
		return
	}
	var st *vault.Store
	var err error
	if create {
		st, err = vault.Create(a.vaultPath, []byte(req.Password))
	} else {
		st, err = vault.Open(a.vaultPath, []byte(req.Password))
	}
	if err != nil {
		if err == secret.ErrWrongPassword {
			writeErr(w, 401, "wrong password")
			return
		}
		writeErr(w, 500, "could not open vault")
		return
	}
	session := randHex(32)
	srv := server.New(st, server.Options{ControlSession: session})
	a.store, a.srv, a.planes, a.session = st, srv, srv.PlanesHandler(), session
	http.SetCookie(w, &http.Cookie{
		Name: "sv_session", Value: session, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, 200, map[string]any{"unlocked": true, "use_token": srv.UseToken()})
}

func (a *App) lock(w http.ResponseWriter, r *http.Request) {
	if !a.hasSession(r) { // only the human's session may seal the vault (else loopback DoS)
		writeErr(w, 401, "unauthorized")
		return
	}
	_ = a.lockNow()
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, 200, map[string]any{"unlocked": false})
}

// proxy forwards the vault planes to the unlocked server, or 423 if locked.
func (a *App) proxy(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	h := a.planes
	a.mu.Unlock()
	if h == nil {
		writeErr(w, 423, "locked — unlock the vault first")
		return
	}
	h.ServeHTTP(w, r)
}

// --- helpers ---

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"error": msg})
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// loopbackGuard rejects any non-loopback client: the GUI (control plane + secret
// input) is for the human at the drive only, never the network.
func loopbackGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
			http.Error(w, "loopback only", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func openBrowser(url string) error {
	switch runtime.GOOS {
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		return exec.Command("open", url).Start()
	default:
		return exec.Command("xdg-open", url).Start()
	}
}
