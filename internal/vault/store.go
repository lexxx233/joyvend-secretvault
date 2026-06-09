package vault

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"mykeep.ai/vault/internal/secret"
)

// ErrNotFound is returned when a credential name is unknown.
var ErrNotFound = errors.New("vault: credential not found")

var nameRe = mustNameRe()

// Store is the in-RAM vault: the decrypted document, the keyring, and the set of
// credentials enabled for this session (reset on every Open — DESIGN.md §6).
type Store struct {
	mu      sync.Mutex
	path    string
	key     *secret.Keyring
	doc     *vaultDoc
	enabled map[string]bool
}

// Create initialises a new sealed vault file at path under password.
func Create(path string, password []byte) (*Store, error) {
	if _, err := os.Stat(path); err == nil {
		return nil, fmt.Errorf("vault: %s already exists", path)
	}
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	doc := &vaultDoc{
		Version:     CurrentVersion,
		FPSalt:      salt,
		Credentials: map[string]*Credential{},
	}
	pt, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	key, file, err := secret.Create(password, pt)
	if err != nil {
		return nil, err
	}
	s := &Store{path: path, key: key, doc: doc, enabled: map[string]bool{}}
	if err := s.writeFile(file); err != nil {
		return nil, err
	}
	return s, nil
}

// Open decrypts an existing vault file. Session-enable state starts empty.
func Open(path string, password []byte) (*Store, error) {
	file, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, pt, err := secret.Open(password, file)
	if err != nil {
		return nil, err
	}
	var doc vaultDoc
	if err := json.Unmarshal(pt, &doc); err != nil {
		key.Zero()
		return nil, fmt.Errorf("vault: corrupt document: %w", err)
	}
	if doc.Version != CurrentVersion {
		key.Zero()
		return nil, fmt.Errorf("vault: unsupported version %d (want %d)", doc.Version, CurrentVersion)
	}
	if doc.Credentials == nil {
		doc.Credentials = map[string]*Credential{}
	}
	return &Store{path: path, key: key, doc: &doc, enabled: map[string]bool{}}, nil
}

// CreateWithDEK initialises a new vault at path keyed by an externally-supplied DEK
// (mykeep suite mode). The file is headerless and NOT password-openable — the suite
// aggregator owns key derivation and unlocks every component with one master key.
func CreateWithDEK(path string, dek []byte) (*Store, error) {
	if _, err := os.Stat(path); err == nil {
		return nil, fmt.Errorf("vault: %s already exists", path)
	}
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	key, err := secret.FromDEK(dek)
	if err != nil {
		return nil, err
	}
	doc := &vaultDoc{
		Version:     CurrentVersion,
		FPSalt:      salt,
		Credentials: map[string]*Credential{},
	}
	s := &Store{path: path, key: key, doc: doc, enabled: map[string]bool{}}
	if err := s.save(); err != nil {
		return nil, err
	}
	return s, nil
}

// OpenWithDEK decrypts an existing headerless suite vault file under the injected DEK.
// A standalone (JVS1, password-keyed) file yields secret.ErrStandaloneFile.
func OpenWithDEK(path string, dek []byte) (*Store, error) {
	file, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, pt, err := secret.OpenSealed(dek, file)
	if err != nil {
		return nil, err
	}
	var doc vaultDoc
	if err := json.Unmarshal(pt, &doc); err != nil {
		key.Zero()
		return nil, fmt.Errorf("vault: corrupt document: %w", err)
	}
	if doc.Version != CurrentVersion {
		key.Zero()
		return nil, fmt.Errorf("vault: unsupported version %d (want %d)", doc.Version, CurrentVersion)
	}
	if doc.Credentials == nil {
		doc.Credentials = map[string]*Credential{}
	}
	return &Store{path: path, key: key, doc: &doc, enabled: map[string]bool{}}, nil
}

// Close re-seals and wipes the key (idle auto-lock and shutdown both call this).
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key == nil {
		return nil
	}
	err := s.save()
	s.key.Zero()
	s.key = nil
	return err
}

// --- control plane: credential CRUD (human only) ---

// Put adds or replaces a credential (DESIGN.md §2 — control plane). It validates
// the shape and persists immediately.
func (s *Store) Put(name string, c *Credential) error {
	if !nameRe.MatchString(name) {
		return fmt.Errorf("vault: invalid credential name %q", name)
	}
	if err := validateCredential(c); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now().UTC()
	}
	s.doc.Credentials[name] = c
	return s.save()
}

// Delete removes a credential.
func (s *Store) Delete(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.doc.Credentials[name]; !ok {
		return ErrNotFound
	}
	delete(s.doc.Credentials, name)
	delete(s.enabled, name)
	return s.save()
}

// Enable sets the per-session enable flag (not persisted; reset on Open).
func (s *Store) Enable(name string, on bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.doc.Credentials[name]; !ok {
		return ErrNotFound
	}
	s.enabled[name] = on
	return nil
}

// Meta returns the secret-free view of one credential.
func (s *Store) Meta(name string) (CredentialMeta, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.doc.Credentials[name]
	if !ok {
		return CredentialMeta{}, ErrNotFound
	}
	return s.metaLocked(name, c), nil
}

// List returns secret-free metadata for all credentials.
func (s *Store) List() []CredentialMeta {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]CredentialMeta, 0, len(s.doc.Credentials))
	for name, c := range s.doc.Credentials {
		out = append(out, s.metaLocked(name, c))
	}
	return out
}

func (s *Store) metaLocked(name string, c *Credential) CredentialMeta {
	return CredentialMeta{
		Name:        name,
		Type:        c.Type,
		AllowHosts:  c.AllowHosts,
		ReadTier:    c.ReadTier,
		WriteTier:   c.WriteTier,
		Enabled:     s.enabled[name],
		ExpiresAt:   c.ExpiresAt,
		Fingerprint: s.fingerprint(c.Secret),
		CreatedAt:   c.CreatedAt,
	}
}

// fingerprint is a salted hash, never the raw value and never an unsalted hash that
// an agent could turn into a brute-force oracle (SECURITY.md, red-team finding).
func (s *Store) fingerprint(value string) string {
	h := sha256.New()
	h.Write(s.doc.FPSalt)
	h.Write([]byte(value))
	return hex.EncodeToString(h.Sum(nil))[:12]
}

// --- use plane support (internal) ---

// lookup returns the credential and whether it is enabled for this session. The
// caller (the fetch pipeline) is the only consumer of the plaintext secret.
func (s *Store) lookup(name string) (*Credential, bool, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.doc.Credentials[name]
	if !ok {
		return nil, false, false
	}
	return c, s.enabled[name], true
}

// --- audit ---

// AppendAudit hash-chains and appends an entry, then persists.
func (s *Store) AppendAudit(e AuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := ""
	if n := len(s.doc.Audit); n > 0 {
		prev = s.doc.Audit[n-1].Hash
	}
	e.PrevHash = prev
	e.Hash = auditHash(prev, e)
	s.doc.Audit = append(s.doc.Audit, e)
	return s.save()
}

// Audit returns a copy of the audit log (human-only; not exposed on the agent plane).
func (s *Store) Audit() []AuditEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]AuditEntry(nil), s.doc.Audit...)
}

// VerifyAudit walks the hash chain and reports the first break.
func (s *Store) VerifyAudit() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := ""
	for i, e := range s.doc.Audit {
		if e.PrevHash != prev {
			return fmt.Errorf("audit: prev_hash break at row %d", i)
		}
		if e.Hash != auditHash(prev, e) {
			return fmt.Errorf("audit: row_hash mismatch at row %d", i)
		}
		prev = e.Hash
	}
	return nil
}

// ClearAuditBefore drops entries older than cutoff and re-anchors the chain
// (user-managed retention — DESIGN.md §7).
func (s *Store) ClearAuditBefore(cutoff time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.doc.Audit[:0:0]
	prev := ""
	dropped := 0
	for _, e := range s.doc.Audit {
		if e.Time.Before(cutoff) {
			dropped++
			continue
		}
		e.PrevHash = prev
		e.Hash = auditHash(prev, e)
		kept = append(kept, e)
		prev = e.Hash
	}
	s.doc.Audit = kept
	return dropped, s.save()
}

func auditHash(prev string, e AuditEntry) string {
	h := sha256.New()
	io.WriteString(h, prev)
	fmt.Fprintf(h, "\x00%s\x00%s\x00%s\x00%s\x00%s\x00%d\x00%d\x00%s\x00%d",
		e.Time.UTC().Format(time.RFC3339Nano), e.Credential, e.Method, e.Host,
		e.Decision, e.Status, e.Bytes, e.Source, e.LatencyMS)
	return hex.EncodeToString(h.Sum(nil))
}

// --- persistence ---

func (s *Store) save() error {
	if s.key == nil {
		return errors.New("vault: locked")
	}
	pt, err := json.Marshal(s.doc)
	if err != nil {
		return err
	}
	file, err := s.key.Seal(pt)
	if err != nil {
		return err
	}
	return s.writeFile(file)
}

// writeFile writes atomically: temp file in the same dir, then rename.
func (s *Store) writeFile(file []byte) error {
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".vault-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(file); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, s.path)
}
