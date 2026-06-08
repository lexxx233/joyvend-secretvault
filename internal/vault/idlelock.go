package vault

import (
	"sync"
	"time"
)

// IdleLock tracks last activity and reports when the idle window has elapsed, so the
// runtime can zero the key and re-lock (DESIGN.md §6). Clock is injectable for tests.
type IdleLock struct {
	mu      sync.Mutex
	last    time.Time
	timeout time.Duration
	now     func() time.Time
}

func NewIdleLock(timeout time.Duration, now func() time.Time) *IdleLock {
	if now == nil {
		now = time.Now
	}
	return &IdleLock{last: now(), timeout: timeout, now: now}
}

// Touch records activity.
func (l *IdleLock) Touch() {
	l.mu.Lock()
	l.last = l.now()
	l.mu.Unlock()
}

// Expired reports whether the idle window has elapsed (timeout<=0 never expires).
func (l *IdleLock) Expired() bool {
	if l.timeout <= 0 {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.now().Sub(l.last) >= l.timeout
}
