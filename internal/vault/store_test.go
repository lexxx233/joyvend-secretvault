package vault

import (
	"path/filepath"
	"testing"
	"time"
)

func newCred() *Credential {
	return &Credential{
		Type:       AuthBearer,
		Secret:     "supersecretvalue",
		AllowHosts: []string{"api.example.com"},
		ReadTier:   TierAuto,
		WriteTier:  TierConfirm,
	}
}

func mkStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vault.json.enc")
	s, err := Create(path, []byte("pw"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return s, path
}

func TestStoreCRUDAndMetaHasNoSecret(t *testing.T) {
	s, _ := mkStore(t)
	if err := s.Put("gh", newCred()); err != nil {
		t.Fatalf("Put: %v", err)
	}
	m, err := s.Meta("gh")
	if err != nil {
		t.Fatalf("Meta: %v", err)
	}
	if m.Fingerprint == "" {
		t.Fatal("meta has no fingerprint")
	}
	// Meta carries no secret field at all; ensure list works and Delete works.
	if len(s.List()) != 1 {
		t.Fatalf("List len = %d", len(s.List()))
	}
	if err := s.Delete("gh"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Meta("gh"); err != ErrNotFound {
		t.Fatalf("Meta after delete = %v", err)
	}
}

func TestFingerprintSaltedAndStable(t *testing.T) {
	s1, _ := mkStore(t)
	s2, _ := mkStore(t)
	_ = s1.Put("a", newCred())
	_ = s2.Put("a", newCred())
	f1, _ := s1.Meta("a")
	f2, _ := s2.Meta("a")
	if f1.Fingerprint == f2.Fingerprint {
		t.Fatal("same secret yields same fingerprint across vaults (unsalted oracle)")
	}
	again, _ := s1.Meta("a")
	if again.Fingerprint != f1.Fingerprint {
		t.Fatal("fingerprint not stable within a vault")
	}
}

func TestSessionEnableResetsOnReopen(t *testing.T) {
	s, path := mkStore(t)
	_ = s.Put("a", newCred())
	if _, en, _ := s.lookup("a"); en {
		t.Fatal("credential enabled by default")
	}
	_ = s.Enable("a", true)
	if _, en, _ := s.lookup("a"); !en {
		t.Fatal("Enable did not take")
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	s2, err := Open(path, []byte("pw"))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if _, ok := s2.doc.Credentials["a"]; !ok {
		t.Fatal("credential not persisted")
	}
	if _, en, _ := s2.lookup("a"); en {
		t.Fatal("enable state leaked across sessions")
	}
}

func TestAuditChainVerifyAndTamper(t *testing.T) {
	s, _ := mkStore(t)
	for i := 0; i < 4; i++ {
		if err := s.AppendAudit(AuditEntry{Time: time.Now().UTC(), Credential: "a", Method: "GET", Decision: "allowed", Status: 200}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	if err := s.VerifyAudit(); err != nil {
		t.Fatalf("verify clean chain: %v", err)
	}
	// Tamper a middle row.
	s.doc.Audit[1].Status = 500
	if err := s.VerifyAudit(); err == nil {
		t.Fatal("tampered audit row passed verification")
	}
}

func TestValidateRejectsBadCredentials(t *testing.T) {
	s, _ := mkStore(t)
	bad := []*Credential{
		{Type: AuthBearer, Secret: "", AllowHosts: []string{"x.com"}},                               // no secret
		{Type: AuthBearer, Secret: "x", AllowHosts: nil},                                            // empty allowlist
		{Type: AuthCustom, Secret: "x", Template: "no placeholder", AllowHosts: []string{"x.com"}},  // bad template
		{Type: "weird", Secret: "x", AllowHosts: []string{"x.com"}},                                 // unknown type
		{Type: AuthBasic, Secret: "x", AllowHosts: []string{"x.com"}},                               // basic w/o username
		{Type: AuthHeader, Secret: "x", HeaderName: "Authorization", AllowHosts: []string{"x.com"}}, // reserved header
	}
	for i, c := range bad {
		if err := s.Put("c", c); err == nil {
			t.Errorf("bad credential %d accepted", i)
		}
	}
}

func TestInvalidNameRejected(t *testing.T) {
	s, _ := mkStore(t)
	if err := s.Put("has space", newCred()); err == nil {
		t.Fatal("invalid name accepted")
	}
}
