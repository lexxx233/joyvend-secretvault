package vault

import (
	"sync"
	"time"
)

// limiter is a per-credential token bucket. perMin<=0 means unlimited.
type limiter struct {
	mu  sync.Mutex
	b   map[string]*bucket
	now func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter(now func() time.Time) *limiter {
	return &limiter{b: map[string]*bucket{}, now: now}
}

func (l *limiter) allow(name string, perMin int) bool {
	if perMin <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	rate := float64(perMin) / 60.0 // tokens per second
	cap := float64(perMin)
	now := l.now()
	bk := l.b[name]
	if bk == nil {
		bk = &bucket{tokens: cap, last: now}
		l.b[name] = bk
	}
	bk.tokens += now.Sub(bk.last).Seconds() * rate
	if bk.tokens > cap {
		bk.tokens = cap
	}
	bk.last = now
	if bk.tokens < 1 {
		return false
	}
	bk.tokens--
	return true
}
