package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"mykeep.ai/secretvault/internal/vault"
)

// pendingApprover realises the "in-RAM pending + GUI decide, synchronous long-poll"
// approval mechanism (DESIGN.md §5). A write-tier Fetch blocks here until the human
// decides via the control plane, or the timeout fires (fail-closed → deny). The
// agent cannot reach decide(): it lives on the loopback-only control plane.
type pendingApprover struct {
	mu      sync.Mutex
	pending map[string]*pendingReq
	timeout time.Duration
}

type pendingReq struct {
	ID         string    `json:"id"`
	Credential string    `json:"credential"`
	Method     string    `json:"method"`
	Host       string    `json:"host"`
	Created    time.Time `json:"created"`
	ch         chan bool
}

func newPendingApprover(timeout time.Duration) *pendingApprover {
	return &pendingApprover{pending: map[string]*pendingReq{}, timeout: timeout}
}

// Confirm blocks until a human decides or the timeout elapses (fail-closed).
func (p *pendingApprover) Confirm(ctx context.Context, r vault.ConfirmRequest) (bool, error) {
	pr := &pendingReq{
		ID:         randID(),
		Credential: r.Credential,
		Method:     r.Method,
		Host:       r.Host,
		Created:    time.Now().UTC(),
		ch:         make(chan bool, 1),
	}
	p.mu.Lock()
	p.pending[pr.ID] = pr
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		delete(p.pending, pr.ID)
		p.mu.Unlock()
	}()

	timer := time.NewTimer(p.timeout)
	defer timer.Stop()
	select {
	case ok := <-pr.ch:
		return ok, nil
	case <-timer.C:
		return false, nil // fail-closed
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

func (p *pendingApprover) list() []pendingReq {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]pendingReq, 0, len(p.pending))
	for _, pr := range p.pending {
		out = append(out, pendingReq{ID: pr.ID, Credential: pr.Credential, Method: pr.Method, Host: pr.Host, Created: pr.Created})
	}
	return out
}

func (p *pendingApprover) decide(id string, approve bool) bool {
	p.mu.Lock()
	pr, ok := p.pending[id]
	p.mu.Unlock()
	if !ok {
		return false
	}
	select {
	case pr.ch <- approve:
		return true
	default:
		return false
	}
}

func randID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
