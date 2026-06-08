// Command secretvault runs the SecretVault broker: it unlocks (or creates) the
// encrypted vault file and serves the two planes (DESIGN.md). The control plane
// (/api/vault) is always loopback-only; the use plane (/v1/vault) is loopback-only
// unless --lan is passed. Pure Go, no CGo.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/lexxx233/joyvend-secretvault/internal/server"
	"github.com/lexxx233/joyvend-secretvault/internal/vault"
)

func main() {
	var (
		path    = flag.String("vault", "joyvend_kb/vault.json.enc", "path to the encrypted vault file")
		addr    = flag.String("addr", "127.0.0.1:8770", "listen address")
		lan     = flag.Bool("lan", false, "expose the USE plane on the LAN (control plane stays loopback-only)")
		idleMin = flag.Int("idle", 15, "idle minutes before auto-lock (0 disables)")
	)
	flag.Parse()

	if err := run(*path, *addr, *lan, time.Duration(*idleMin)*time.Minute); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(path, addr string, lan bool, idle time.Duration) error {
	pw := passphrase()
	if len(pw) == 0 {
		return fmt.Errorf("empty passphrase")
	}

	var store *vault.Store
	var err error
	if _, statErr := os.Stat(path); statErr == nil {
		store, err = vault.Open(path, pw)
	} else {
		if mkErr := os.MkdirAll(dir(path), 0o700); mkErr != nil {
			return mkErr
		}
		store, err = vault.Create(path, pw)
		fmt.Println("• created a new vault")
	}
	if err != nil {
		return err
	}

	srv := server.New(store, server.Options{EnableLAN: lan})
	fmt.Printf("\nSecretVault serving on %s  (LAN use plane: %v)\n", addr, lan)
	fmt.Printf("  agent (use)  token: %s\n", srv.UseToken())
	fmt.Printf("  GUI (control) token: %s   ← keep this off the wire\n\n", srv.ControlToken())

	// Idle auto-lock: touch on every request; a watcher zeros the key and exits.
	idleLock := vault.NewIdleLock(idle, time.Now)
	var locked atomic.Bool
	handler := touch(idleLock, srv.Handler())

	httpSrv := &http.Server{Addr: addr, Handler: handler}
	errCh := make(chan error, 1)
	go func() {
		if e := httpSrv.ListenAndServe(); e != nil && e != http.ErrServerClosed {
			errCh <- e
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sig:
			return shutdown(httpSrv, store)
		case e := <-errCh:
			_ = store.Close()
			return e
		case <-ticker.C:
			if idleLock.Expired() && locked.CompareAndSwap(false, true) {
				fmt.Fprintln(os.Stderr, "idle auto-lock — re-launch to unlock")
				return shutdown(httpSrv, store)
			}
		}
	}
}

func shutdown(httpSrv *http.Server, store *vault.Store) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(ctx)
	return store.Close() // final re-seal + zero the key
}

// touch records activity for the idle-lock on every request.
func touch(l *vault.IdleLock, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.Touch()
		next.ServeHTTP(w, r)
	})
}

func passphrase() []byte {
	if v := os.Getenv("JOYVEND_VAULT_PASSPHRASE"); v != "" {
		return []byte(v)
	}
	fmt.Fprint(os.Stderr, "Vault passphrase: ")
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return []byte(strings.TrimRight(line, "\r\n"))
}

func dir(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[:i]
	}
	return "."
}
