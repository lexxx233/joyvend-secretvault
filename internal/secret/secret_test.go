package secret

import (
	"bytes"
	"testing"
)

func init() {
	// Keep argon2 cheap in tests.
	argonTime, argonMemKiB, argonThreads = 1, 8*1024, 1
}

func TestSealOpenRoundTrip(t *testing.T) {
	pw := []byte("correct horse battery staple")
	plain := []byte(`{"version":1,"credentials":{}}`)

	k, file, err := Create(pw, plain)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if bytes.Contains(file, plain) {
		t.Fatal("sealed file contains plaintext")
	}

	_, got, err := Open(pw, file)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round-trip mismatch: %q != %q", got, plain)
	}
	_ = k
}

func TestWrongPasswordFails(t *testing.T) {
	k, file, _ := Create([]byte("right"), []byte("secrets"))
	_ = k
	if _, _, err := Open([]byte("wrong"), file); err != ErrWrongPassword {
		t.Fatalf("wrong password => %v, want ErrWrongPassword", err)
	}
}

func TestTamperDetected(t *testing.T) {
	_, file, _ := Create([]byte("pw"), []byte("secrets"))
	// Flip a byte in the body (after the header).
	tampered := append([]byte(nil), file...)
	tampered[len(tampered)-1] ^= 0xff
	if _, _, err := Open([]byte("pw"), tampered); err == nil {
		t.Fatal("tampered body opened without error")
	}
}

func TestReSealUsesFreshNonceSameKey(t *testing.T) {
	pw := []byte("pw")
	k, _, _ := Create(pw, []byte("v1"))
	a, _ := k.Seal([]byte("hello"))
	b, _ := k.Seal([]byte("hello"))
	if bytes.Equal(a, b) {
		t.Fatal("two seals of same plaintext are byte-identical (nonce reuse?)")
	}
	// Both decrypt back via a re-open.
	_, pt, err := Open(pw, b)
	if err != nil || string(pt) != "hello" {
		t.Fatalf("re-seal/open: %v %q", err, pt)
	}
}

func TestZeroWipesKey(t *testing.T) {
	k, _, _ := Create([]byte("pw"), []byte("x"))
	k.Zero()
	for i, b := range k.dek {
		if b != 0 {
			t.Fatalf("dek[%d] = %d after Zero", i, b)
		}
	}
}
