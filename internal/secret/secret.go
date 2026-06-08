// Package secret implements SecretVault's at-rest crypto: a password-derived KEK
// (argon2id) wrapping a random 256-bit DEK, which seals the whole vault JSON as one
// AES-256-GCM blob (DESIGN.md §1). The DEK lives only in RAM while unlocked; Zero
// wipes it on lock. Pure Go, no CGo.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
)

// Argon2id cost. Package-level so tests can lower it; production keeps these.
var (
	argonTime    uint32 = 1
	argonMemKiB  uint32 = 64 * 1024 // 64 MiB
	argonThreads uint8  = 4
)

const (
	magic      = "JVS1"
	saltLen    = 16
	nonceLen   = 12 // GCM standard nonce
	dekLen     = 32 // AES-256
	wrappedLen = dekLen + 16
	headerLen  = len(magic) + saltLen + nonceLen + wrappedLen
)

// ErrWrongPassword is returned when the password fails to unwrap the DEK.
var ErrWrongPassword = errors.New("secret: wrong password or corrupt vault file")

// Keyring holds the unwrapped DEK plus the constant file header (salt + wrapped
// DEK), so re-sealing reuses the same key and header and only re-encrypts the body.
type Keyring struct {
	dek    []byte
	header []byte // magic|salt|dekNonce|wrappedDEK — emitted verbatim on every seal
}

func deriveKEK(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, argonTime, argonMemKiB, argonThreads, dekLen)
}

// Create initialises a fresh vault: random salt + random DEK, wrapped under the
// password-derived KEK. Returns the keyring and the first sealed file for plaintext.
func Create(password, plaintext []byte) (*Keyring, []byte, error) {
	salt := make([]byte, saltLen)
	dek := make([]byte, dekLen)
	dekNonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, nil, err
	}
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, nil, err
	}
	if _, err := io.ReadFull(rand.Reader, dekNonce); err != nil {
		return nil, nil, err
	}
	kekGCM, err := gcm(deriveKEK(password, salt))
	if err != nil {
		return nil, nil, err
	}
	wrapped := kekGCM.Seal(nil, dekNonce, dek, nil)

	header := make([]byte, 0, headerLen)
	header = append(header, magic...)
	header = append(header, salt...)
	header = append(header, dekNonce...)
	header = append(header, wrapped...)

	k := &Keyring{dek: dek, header: header}
	file, err := k.Seal(plaintext)
	if err != nil {
		return nil, nil, err
	}
	return k, file, nil
}

// Open unwraps the DEK from a sealed file using the password and returns the
// keyring plus the decrypted plaintext. A wrong password yields ErrWrongPassword.
func Open(password, file []byte) (*Keyring, []byte, error) {
	if len(file) < headerLen || string(file[:len(magic)]) != magic {
		return nil, nil, ErrWrongPassword
	}
	off := len(magic)
	salt := file[off : off+saltLen]
	off += saltLen
	dekNonce := file[off : off+nonceLen]
	off += nonceLen
	wrapped := file[off : off+wrappedLen]
	off += wrappedLen

	kekGCM, err := gcm(deriveKEK(password, salt))
	if err != nil {
		return nil, nil, err
	}
	dek, err := kekGCM.Open(nil, dekNonce, wrapped, nil)
	if err != nil {
		return nil, nil, ErrWrongPassword
	}
	k := &Keyring{dek: dek, header: append([]byte(nil), file[:headerLen]...)}
	pt, err := k.open(file[headerLen:])
	if err != nil {
		// DEK unwrapped but body is corrupt/tampered.
		return nil, nil, err
	}
	return k, pt, nil
}

// Seal re-encrypts plaintext under the keyring's DEK and returns a full file
// (constant header + fresh body). Each call uses a fresh random body nonce.
func (k *Keyring) Seal(plaintext []byte) ([]byte, error) {
	bodyGCM, err := gcm(k.dek)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ct := bodyGCM.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, 0, len(k.header)+nonceLen+len(ct))
	out = append(out, k.header...)
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

func (k *Keyring) open(body []byte) ([]byte, error) {
	if len(body) < nonceLen {
		return nil, errors.New("secret: truncated vault body")
	}
	bodyGCM, err := gcm(k.dek)
	if err != nil {
		return nil, err
	}
	pt, err := bodyGCM.Open(nil, body[:nonceLen], body[nonceLen:], nil)
	if err != nil {
		return nil, errors.New("secret: vault body failed authentication (tampered or corrupt)")
	}
	return pt, nil
}

// Zero wipes the DEK from memory on lock. After Zero the keyring is unusable.
func (k *Keyring) Zero() {
	for i := range k.dek {
		k.dek[i] = 0
	}
}

func gcm(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
