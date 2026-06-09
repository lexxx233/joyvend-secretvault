// Package component is the public integration surface of the mykeep vault component.
//
// Standalone, vault ships as its own binary (cmd/vault) that prompts for a password
// and derives its own key. To compose vault into the mykeep *suite* (one binary, one
// unlock for several components), the suite aggregator lives in a separate Go module
// and cannot import vault's internal/ packages. This package is the thin, stable
// bridge: it lives inside the mykeep.ai/vault module (so it may reach internal/), and
// exposes only stdlib + []byte across the boundary.
//
// The contract is duck-typed — the aggregator declares the interface it needs and a
// *Component satisfies it structurally; nothing here imports the aggregator.
package component

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"mykeep.ai/vault/internal/server"
	"mykeep.ai/vault/internal/vault"
)

// ID is vault's stable identifier within the suite.
const ID = "vault"

// FetchRequest / FetchResponse are the by-reference request/response — the secret never
// crosses them. Re-exported (aliases to the internal types) so a suite aggregator, which
// cannot import vault's internal/ packages, can drive vault by reference programmatically
// — e.g. to back Foundry's foundry.vault.fetch so a sandboxed tool can act as the user
// without ever seeing a credential.
type (
	FetchRequest  = vault.FetchRequest
	FetchResponse = vault.FetchResponse
)

// ErrLocked is returned by Fetch when the component has not been unlocked.
var ErrLocked = errors.New("vault: locked")

// vaultFile is vault's encrypted store, resolved inside the suite data dir.
const vaultFile = "vault.json.enc"

// Options is everything the host (standalone cmd or the suite aggregator) supplies.
type Options struct {
	DataDir         string        // suite data dir; vault.json.enc lives directly inside it
	Version         string        // host binary version
	EnableLAN       bool          // expose the USE plane on the LAN (control plane stays loopback)
	UseToken        string        // agent token for /v1/vault (generated if empty)
	ControlToken    string        // control token for /api/vault (generated if empty)
	ControlSession  string        // GUI session-cookie value also accepted on the control plane
	SessionCookie   string        // name of the session cookie (default "sv_session"; the suite uses "mykeep_session")
	ApprovalTimeout time.Duration // how long a write blocks for a human decision
}

// Component is the vault capability. Construct it LOCKED with New; Unlock activates it
// with an injected key; Mount attaches its two planes; Lock tears it down.
type Component struct {
	opts  Options
	path  string
	store *vault.Store
	srv   *server.Server
}

// New builds a locked component bound to a data dir. Cheap: no crypto, no secret I/O.
func New(opts Options) (*Component, error) {
	return &Component{opts: opts, path: filepath.Join(opts.DataDir, vaultFile)}, nil
}

// ID returns the stable component identifier.
func (c *Component) ID() string { return ID }

// FirstLaunch reports whether the vault store has never been created in this data dir.
func (c *Component) FirstLaunch() bool {
	_, err := os.Stat(c.path)
	return os.IsNotExist(err)
}

// Unlock activates vault with an externally supplied 32-byte DEK. It opens (or, on
// first launch, creates) the headerless encrypted store keyed by that DEK; it does
// NOT run its own argon2id. The dek slice is copied internally — the caller keeps
// ownership of its slice.
func (c *Component) Unlock(_ context.Context, dek []byte) error {
	var (
		st  *vault.Store
		err error
	)
	if c.FirstLaunch() {
		if mkErr := os.MkdirAll(c.opts.DataDir, 0o700); mkErr != nil {
			return mkErr
		}
		st, err = vault.CreateWithDEK(c.path, dek)
	} else {
		st, err = vault.OpenWithDEK(c.path, dek)
	}
	if err != nil {
		return err
	}
	c.store = st
	c.srv = server.New(st, server.Options{
		EnableLAN:       c.opts.EnableLAN,
		UseToken:        c.opts.UseToken,
		ControlToken:    c.opts.ControlToken,
		ControlSession:  c.opts.ControlSession,
		SessionCookie:   c.opts.SessionCookie,
		ApprovalTimeout: c.opts.ApprovalTimeout,
	})
	return nil
}

// Mount attaches vault's USE plane (/v1/vault/) and CONTROL plane (/api/vault/) onto
// the shared suite mux. Both keep their own guards; the control plane stays
// loopback-only and unreachable by a co-resident agent.
func (c *Component) Mount(mux *http.ServeMux) {
	if c.srv != nil {
		c.srv.Mount(mux)
	}
}

// UseToken / ControlToken expose the minted tokens (after Unlock) so the aggregator
// can present them in the merged snippet / GUI. Empty before Unlock.
func (c *Component) UseToken() string {
	if c.srv == nil {
		return ""
	}
	return c.srv.UseToken()
}

func (c *Component) ControlToken() string {
	if c.srv == nil {
		return ""
	}
	return c.srv.ControlToken()
}

// Fetch makes an authenticated request AS the user by credential reference: vault attaches
// the secret server-side and returns the response, which never contains it. source is an
// audit label (e.g. the calling tool). The same allowlist + SSRF guard + write-approval
// gate as the HTTP use plane apply. ErrLocked if not unlocked.
func (c *Component) Fetch(ctx context.Context, source string, fr FetchRequest) (FetchResponse, error) {
	if c.srv == nil {
		return FetchResponse{}, ErrLocked
	}
	resp, ferr := c.srv.Engine().Fetch(ctx, source, fr)
	if ferr != nil {
		return FetchResponse{}, ferr
	}
	return resp, nil
}

// Lock re-seals and zeroizes the key. Idempotent.
func (c *Component) Lock() error {
	if c.store == nil {
		return nil
	}
	err := c.store.Close()
	c.store, c.srv = nil, nil
	return err
}
