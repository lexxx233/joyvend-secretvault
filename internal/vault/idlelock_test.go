package vault

import (
	"testing"
	"time"
)

func TestIdleLock(t *testing.T) {
	now := time.Unix(1000, 0)
	clock := func() time.Time { return now }
	l := NewIdleLock(10*time.Second, clock)

	if l.Expired() {
		t.Fatal("fresh lock reported expired")
	}
	now = now.Add(11 * time.Second)
	if !l.Expired() {
		t.Fatal("11s idle with 10s timeout should expire")
	}
	l.Touch()
	if l.Expired() {
		t.Fatal("Touch did not reset the idle window")
	}
	now = now.Add(5 * time.Second)
	if l.Expired() {
		t.Fatal("5s < 10s should not expire")
	}
}

func TestIdleLockZeroNeverExpires(t *testing.T) {
	if NewIdleLock(0, nil).Expired() {
		t.Fatal("zero timeout must never expire")
	}
}
