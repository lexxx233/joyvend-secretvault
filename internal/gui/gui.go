// Package gui serves SecretVault's local web app: a loopback dashboard (opened in
// the browser) that unlocks the vault with a password, then lets the human add and
// manage credentials, approve writes, and read the audit log. Secret input IS the
// control plane (DESIGN.md §2), so it lives here, gated by a password-derived session
// the agent can never obtain. Pure Go, no toolkit, no CGo.
package gui

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"github.com/lexxx233/joyvend-secretvault/internal/secret"
	"github.com/lexxx233/joyvend-secretvault/internal/server"
	"github.com/lexxx233/joyvend-secretvault/internal/vault"
)

//go:embed web/index.html
var indexHTML []byte

// App owns the GUI lifecycle: locked until the human unlocks via the browser.
type App struct {
	vaultPath string
	addr      string

	mu      sync.Mutex
	store   *vault.Store
	srv     *server.Server
	planes  http.Handler
	session string
}

// New builds a GUI app over a vault file path.
func New(vaultPath, addr string) *App {
	return &App{vaultPath: vaultPath, addr: addr}
}

// Run serves the GUI and opens the browser, blocking until ctx is done.
func (a *App) Run(ctx context.Context) error {
	httpSrv := &http.Server{Addr: a.addr, Handler: loopbackGuard(a.handler())}
	errCh := make(chan error, 1)
	go func() {
		if e := httpSrv.ListenAndServe(); e != nil && e != http.ErrServerClosed {
			errCh <- e
		}
	}()
	_ = openBrowser("http://" + a.addr)

	select {
	case <-ctx.Done():
	case e := <-errCh:
		return e
	}
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(sctx)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.store != nil {
		return a.store.Close()
	}
	return nil
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
	_, _ = w.Write(indexHTML)
}

func (a *App) state(w http.ResponseWriter, _ *http.Request) {
	a.mu.Lock()
	unlocked := a.srv != nil
	var useToken string
	if a.srv != nil {
		useToken = a.srv.UseToken()
	}
	a.mu.Unlock()
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
	if _, err := os.Stat(a.vaultPath); err == nil {
		writeErr(w, 409, "already set up")
		return
	}
	a.open(w, r, true)
}

func (a *App) unlock(w http.ResponseWriter, r *http.Request) {
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

func (a *App) lock(w http.ResponseWriter, _ *http.Request) {
	a.mu.Lock()
	st := a.store
	a.store, a.srv, a.planes, a.session = nil, nil, nil, ""
	a.mu.Unlock()
	if st != nil {
		_ = st.Close()
	}
	http.SetCookie(w, &http.Cookie{Name: "sv_session", Value: "", Path: "/", MaxAge: -1})
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
