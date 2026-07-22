package client

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	vaultEnvelopeVersion = 1
	argonMemoryKiB       = 64 * 1024
	argonPasses          = 3
	argonParallelism     = 4
)

var ErrInvalidVaultEnvelope = errors.New("invalid vault envelope")

// Vault holds client-generated key material during bootstrap. Call Clear when
// the material has been sent or the client no longer needs it.
type Vault struct {
	Key              []byte
	RecoveryKey      string
	PasswordEnvelope []byte
	RecoveryEnvelope []byte
}

type vaultEnvelope struct {
	Version     int    `json:"version"`
	KDF         string `json:"kdf"`
	MemoryKiB   uint32 `json:"memory_kib,omitempty"`
	Passes      uint32 `json:"passes,omitempty"`
	Parallelism uint8  `json:"parallelism,omitempty"`
	Salt        []byte `json:"salt,omitempty"`
	Nonce       []byte `json:"nonce"`
	Ciphertext  []byte `json:"ciphertext"`
}

// NewVault creates an empty vault's random key, then wraps it separately for
// the master password and recovery key. No vault key or recovery key is sent
// to the server in plaintext.
func NewVault(masterPassword []byte, accountID string) (*Vault, error) {
	if err := ValidateMasterPassword(string(masterPassword)); err != nil {
		return nil, err
	}
	if accountID == "" {
		return nil, errors.New("account ID is required")
	}

	vaultKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(vaultKey); err != nil {
		return nil, fmt.Errorf("generate vault key: %w", err)
	}

	recoveryMaterial := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(recoveryMaterial); err != nil {
		clearBytes(vaultKey)
		return nil, fmt.Errorf("generate recovery key: %w", err)
	}
	defer clearBytes(recoveryMaterial)

	passwordEnvelope, err := passwordEnvelope(vaultKey, masterPassword, accountID)
	if err != nil {
		clearBytes(vaultKey)
		return nil, err
	}
	recoveryEnvelope, err := recoveryEnvelope(vaultKey, recoveryMaterial, accountID)
	if err != nil {
		clearBytes(vaultKey)
		return nil, err
	}

	return &Vault{
		Key:              vaultKey,
		RecoveryKey:      base64.RawURLEncoding.EncodeToString(recoveryMaterial),
		PasswordEnvelope: passwordEnvelope,
		RecoveryEnvelope: recoveryEnvelope,
	}, nil
}

// UnlockVaultWithPassword unwraps a vault key after locally deriving the
// password material specified by its versioned envelope.
func UnlockVaultWithPassword(encoded, masterPassword []byte, accountID string) ([]byte, error) {
	envelope, err := decodeVaultEnvelope(encoded)
	if err != nil {
		return nil, err
	}
	if envelope.KDF != "argon2id" || envelope.MemoryKiB < argonMemoryKiB || envelope.Passes < argonPasses || len(envelope.Salt) < 16 {
		return nil, ErrInvalidVaultEnvelope
	}
	derived := argon2.IDKey(masterPassword, envelope.Salt, envelope.Passes, envelope.MemoryKiB, envelope.Parallelism, chacha20poly1305.KeySize)
	defer clearBytes(derived)
	return openVaultKey(envelope, derivePurposeKey(derived, "vault-password-wrap"), accountID)
}

// UnlockVaultWithRecovery unwraps a vault key using the recovery key that was
// displayed once during bootstrap.
func UnlockVaultWithRecovery(encoded []byte, recoveryKey, accountID string) ([]byte, error) {
	envelope, err := decodeVaultEnvelope(encoded)
	if err != nil {
		return nil, err
	}
	if envelope.KDF != "hkdf-sha256" {
		return nil, ErrInvalidVaultEnvelope
	}
	recoveryMaterial, err := base64.RawURLEncoding.DecodeString(recoveryKey)
	if err != nil || len(recoveryMaterial) != chacha20poly1305.KeySize {
		return nil, ErrInvalidVaultEnvelope
	}
	defer clearBytes(recoveryMaterial)
	return openVaultKey(envelope, derivePurposeKey(recoveryMaterial, "vault-recovery-wrap"), accountID)
}

// Clear makes a best-effort attempt to erase the in-memory vault key.
func (v *Vault) Clear() {
	clearBytes(v.Key)
	v.Key = nil
}

func passwordEnvelope(vaultKey, masterPassword []byte, accountID string) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate password salt: %w", err)
	}
	derived := argon2.IDKey(masterPassword, salt, argonPasses, argonMemoryKiB, argonParallelism, chacha20poly1305.KeySize)
	defer clearBytes(derived)
	return sealVaultKey(vaultKey, derivePurposeKey(derived, "vault-password-wrap"), accountID, vaultEnvelope{
		Version:     vaultEnvelopeVersion,
		KDF:         "argon2id",
		MemoryKiB:   argonMemoryKiB,
		Passes:      argonPasses,
		Parallelism: argonParallelism,
		Salt:        salt,
	})
}

func recoveryEnvelope(vaultKey, recoveryMaterial []byte, accountID string) ([]byte, error) {
	return sealVaultKey(vaultKey, derivePurposeKey(recoveryMaterial, "vault-recovery-wrap"), accountID, vaultEnvelope{
		Version: vaultEnvelopeVersion,
		KDF:     "hkdf-sha256",
	})
}

func sealVaultKey(vaultKey, wrappingKey []byte, accountID string, envelope vaultEnvelope) ([]byte, error) {
	defer clearBytes(wrappingKey)
	aead, err := chacha20poly1305.NewX(wrappingKey)
	if err != nil {
		return nil, fmt.Errorf("initialize vault envelope: %w", err)
	}
	envelope.Nonce = make([]byte, aead.NonceSize())
	if _, err := rand.Read(envelope.Nonce); err != nil {
		return nil, fmt.Errorf("generate vault nonce: %w", err)
	}
	envelope.Ciphertext = aead.Seal(nil, envelope.Nonce, vaultKey, vaultAssociatedData(accountID))
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("encode vault envelope: %w", err)
	}
	return encoded, nil
}

func openVaultKey(envelope vaultEnvelope, wrappingKey []byte, accountID string) ([]byte, error) {
	defer clearBytes(wrappingKey)
	aead, err := chacha20poly1305.NewX(wrappingKey)
	if err != nil || len(envelope.Nonce) != aead.NonceSize() {
		return nil, ErrInvalidVaultEnvelope
	}
	key, err := aead.Open(nil, envelope.Nonce, envelope.Ciphertext, vaultAssociatedData(accountID))
	if err != nil || len(key) != chacha20poly1305.KeySize {
		clearBytes(key)
		return nil, ErrInvalidVaultEnvelope
	}
	return key, nil
}

func decodeVaultEnvelope(encoded []byte) (vaultEnvelope, error) {
	var envelope vaultEnvelope
	if err := json.Unmarshal(encoded, &envelope); err != nil || envelope.Version != vaultEnvelopeVersion || len(envelope.Ciphertext) == 0 {
		return vaultEnvelope{}, ErrInvalidVaultEnvelope
	}
	return envelope, nil
}

func derivePurposeKey(material []byte, purpose string) []byte {
	reader := hkdf.New(sha256.New, material, nil, []byte("termkeep/v1/"+purpose))
	key := make([]byte, chacha20poly1305.KeySize)
	_, _ = io.ReadFull(reader, key)
	return key
}

func vaultAssociatedData(accountID string) []byte {
	return []byte("termkeep/vault-envelope/v1/" + accountID)
}

func clearBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
