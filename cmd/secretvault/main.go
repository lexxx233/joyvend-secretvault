// Command secretvault runs the SecretVault broker.
//
//	secretvault            open the local GUI (unlock + manage secrets in the browser)
//	secretvault gui        same as default
//	secretvault serve      headless: unlock at launch (env/stdin), serve the API only
//
// The control plane (/api/vault, secret input) is always loopback-only; the use plane
// (/v1/vault) is loopback-only unless --lan. Pure Go, no CGo.
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

	"mykeep.ai/secretvault/internal/gui"
	"mykeep.ai/secretvault/internal/server"
	"mykeep.ai/secretvault/internal/vault"
)

func main() {
	mode := "gui"
	args := os.Args[1:]
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		mode, args = args[0], args[1:]
	}
	var err error
	switch mode {
	case "gui":
		err = runGUI(args)
	case "serve":
		err = runServe(args)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q (use: gui | serve)\n", mode)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func runGUI(args []string) error {
	fs := flag.NewFlagSet("gui", flag.ExitOnError)
	path := fs.String("vault", "mykeep_kb/vault.json.enc", "path to the encrypted vault file")
	addr := fs.String("addr", "127.0.0.1:8770", "loopback listen address")
	fs.Parse(args)
	if err := os.MkdirAll(dir(*path), 0o700); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	fmt.Printf("\n🔐  SecretVault GUI: http://%s  (opening your browser…)\n", *addr)
	return gui.New(*path, *addr).Run(ctx)
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	path := fs.String("vault", "mykeep_kb/vault.json.enc", "path to the encrypted vault file")
	addr := fs.String("addr", "127.0.0.1:8770", "listen address")
	lan := fs.Bool("lan", false, "expose the USE plane on the LAN (control plane stays loopback)")
	idleMin := fs.Int("idle", 15, "idle minutes before auto-lock (0 disables)")
	fs.Parse(args)

	pw := passphrase()
	if len(pw) == 0 {
		return fmt.Errorf("empty passphrase")
	}
	var store *vault.Store
	var err error
	if _, statErr := os.Stat(*path); statErr == nil {
		store, err = vault.Open(*path, pw)
	} else {
		if mkErr := os.MkdirAll(dir(*path), 0o700); mkErr != nil {
			return mkErr
		}
		store, err = vault.Create(*path, pw)
		fmt.Println("• created a new vault")
	}
	if err != nil {
		return err
	}

	srv := server.New(store, server.Options{EnableLAN: *lan})
	fmt.Printf("\nSecretVault serving on %s  (LAN use plane: %v)\n", *addr, *lan)
	fmt.Printf("  agent (use)  token: %s\n", srv.UseToken())
	fmt.Printf("  GUI (control) token: %s   ← keep this off the wire\n\n", srv.ControlToken())

	idleLock := vault.NewIdleLock(time.Duration(*idleMin)*time.Minute, time.Now)
	var locked atomic.Bool
	httpSrv := &http.Server{Addr: *addr, Handler: touch(idleLock, srv.Handler())}
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
	return store.Close()
}

func touch(l *vault.IdleLock, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.Touch()
		next.ServeHTTP(w, r)
	})
}

func passphrase() []byte {
	if v := os.Getenv("MYKEEP_VAULT_PASSPHRASE"); v != "" {
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
