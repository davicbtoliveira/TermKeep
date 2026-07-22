package client

import (
	"bytes"
	"testing"
)

func TestNewVaultUnlocksWithMasterPassword(t *testing.T) {
	password := []byte("TermKeep#2026")
	vault, err := NewVault(password, "30a89a33-88c6-49fa-ba5c-40c48d43fa20")
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Clear()

	key, err := UnlockVaultWithPassword(vault.PasswordEnvelope, password, "30a89a33-88c6-49fa-ba5c-40c48d43fa20")
	if err != nil {
		t.Fatal(err)
	}
	defer clearBytes(key)
	if !bytes.Equal(key, vault.Key) {
		t.Fatal("master password did not unlock original vault key")
	}
}

func TestVaultRecoveryKeyUnlocksAndTamperedEnvelopeFails(t *testing.T) {
	const accountID = "30a89a33-88c6-49fa-ba5c-40c48d43fa20"
	vault, err := NewVault([]byte("TermKeep#2026"), accountID)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Clear()

	key, err := UnlockVaultWithRecovery(vault.RecoveryEnvelope, vault.RecoveryKey, accountID)
	if err != nil {
		t.Fatal(err)
	}
	defer clearBytes(key)
	if !bytes.Equal(key, vault.Key) {
		t.Fatal("recovery key did not unlock original vault key")
	}

	tampered := append([]byte(nil), vault.PasswordEnvelope...)
	tampered[len(tampered)-1] ^= 1
	if _, err := UnlockVaultWithPassword(tampered, []byte("TermKeep#2026"), accountID); err == nil {
		t.Fatal("tampered vault envelope unlocked")
	}
}
