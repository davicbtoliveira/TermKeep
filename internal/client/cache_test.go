package client

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
)

func TestAuthorizedCacheUnlocksWithoutServer(t *testing.T) {
	password := []byte("TermKeep#2026")
	accountID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	vault, err := NewVault(password, accountID)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Clear()
	cfg := Config{DataDir: filepath.Join(t.TempDir(), "cache")}

	if err := AuthorizeCache(
		cfg,
		"user@example.com",
		accountID,
		vault.PasswordEnvelope,
	); err != nil {
		t.Fatal(err)
	}
	cache, err := OpenCache(cfg, "user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	unlocked, err := cache.Unlock(password)
	if err != nil {
		t.Fatal(err)
	}
	defer clearBytes(unlocked)
	if !bytes.Equal(unlocked, vault.Key) {
		t.Fatal("offline cache unlocked a different vault key")
	}

	stored, err := os.ReadFile(cache.Path())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, password) || bytes.Contains(stored, vault.Key) {
		t.Fatal("cache persisted master password or plaintext vault key")
	}
	info, err := os.Stat(cache.Path())
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("cache mode: want 0600, got %04o", info.Mode().Perm())
	}
}

func TestOfflineMutationIsVisibleAndDurable(t *testing.T) {
	password := []byte("TermKeep#2026")
	accountID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	vault, err := NewVault(password, accountID)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Clear()
	cfg := Config{DataDir: filepath.Join(t.TempDir(), "cache")}
	if err := AuthorizeCache(
		cfg,
		"user@example.com",
		accountID,
		vault.PasswordEnvelope,
	); err != nil {
		t.Fatal(err)
	}
	cache, err := OpenCache(cfg, "user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	item := EncryptedItem{
		ItemID:        "11111111-1111-4111-8111-111111111111",
		SchemaVersion: 1,
		Revision:      1,
		Envelope:      []byte("encrypted"),
	}
	mutation, err := cache.QueueMutation(item, 0)
	if err != nil {
		t.Fatal(err)
	}
	if mutation.MutationID == "" {
		t.Fatal("queued mutation has no stable ID")
	}

	reopened, err := OpenCache(cfg, "user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	items, err := reopened.Items()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || !reflect.DeepEqual(items[0], item) {
		t.Fatalf("offline item not visible after reopen: %+v", items)
	}
	pending, err := reopened.PendingMutations()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || !reflect.DeepEqual(pending[0], mutation) {
		t.Fatalf("mutation not durable after reopen: %+v", pending)
	}
}

func TestSyncResultAtomicallyAdvancesCache(t *testing.T) {
	password := []byte("TermKeep#2026")
	accountID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	vault, err := NewVault(password, accountID)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Clear()
	cfg := Config{DataDir: filepath.Join(t.TempDir(), "cache")}
	if err := AuthorizeCache(
		cfg,
		"user@example.com",
		accountID,
		vault.PasswordEnvelope,
	); err != nil {
		t.Fatal(err)
	}
	cache, err := OpenCache(cfg, "user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	local := EncryptedItem{
		ItemID:        "11111111-1111-4111-8111-111111111111",
		SchemaVersion: 1,
		Revision:      1,
		Envelope:      []byte("local-encrypted"),
	}
	mutation, err := cache.QueueMutation(local, 0)
	if err != nil {
		t.Fatal(err)
	}
	remote := EncryptedItem{
		ItemID:        "22222222-2222-4222-8222-222222222222",
		SchemaVersion: 1,
		Revision:      1,
		Envelope:      []byte("remote-encrypted"),
	}
	if err := cache.ApplySync(
		"7",
		[]string{mutation.MutationID},
		[]EncryptedItem{local, remote},
	); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenCache(cfg, "user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := reopened.SyncSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Cursor != "7" || len(snapshot.Mutations) != 0 {
		t.Fatalf("sync state not durable: %+v", snapshot)
	}
	items, err := reopened.Items()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 ||
		items[0].ItemID != local.ItemID ||
		items[1].ItemID != remote.ItemID {
		t.Fatalf("pulled items not durable: %+v", items)
	}
}

func TestOfflineLoginUnlocksAuthorizedCache(t *testing.T) {
	password := []byte("TermKeep#2026")
	accountID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	vault, err := NewVault(password, accountID)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Clear()
	cfg := Config{
		ServerURL: "https://offline.invalid",
		DataDir:   filepath.Join(t.TempDir(), "cache"),
	}
	if err := AuthorizeCache(
		cfg,
		"user@example.com",
		accountID,
		vault.PasswordEnvelope,
	); err != nil {
		t.Fatal(err)
	}

	result, err := LoginOffline(cfg, LoginInput{
		Email:          "user@example.com",
		MasterPassword: string(password),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer result.Clear()
	if result.AccountID != accountID ||
		result.AccessToken != "" ||
		!bytes.Equal(result.VaultKey, vault.Key) {
		t.Fatalf("unexpected offline login result: %+v", result)
	}
}

func TestLoginWithCacheFallsBackWhenServerIsUnavailable(t *testing.T) {
	password := []byte("TermKeep#2026")
	accountID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	vault, err := NewVault(password, accountID)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Clear()
	server := httptest.NewServer(http.HandlerFunc(func(
		w http.ResponseWriter,
		_ *http.Request,
	) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	cfg := Config{
		ServerURL: server.URL,
		DataDir:   filepath.Join(t.TempDir(), "cache"),
	}
	if err := AuthorizeCache(
		cfg,
		"user@example.com",
		accountID,
		vault.PasswordEnvelope,
	); err != nil {
		t.Fatal(err)
	}

	result, status, err := LoginWithCache(
		context.Background(),
		cfg,
		LoginInput{
			Email:          "user@example.com",
			MasterPassword: string(password),
			Host:           "workstation",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Clear()
	if !result.Offline ||
		status.State != StateUnavailable ||
		!bytes.Equal(result.VaultKey, vault.Key) {
		t.Fatalf("unexpected cached login: result=%+v status=%+v", result, status)
	}
}

func TestMutationSurvivesWriterProcessExit(t *testing.T) {
	password := []byte("TermKeep#2026")
	accountID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	vault, err := NewVault(password, accountID)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Clear()
	dataDir := filepath.Join(t.TempDir(), "cache")
	cfg := Config{DataDir: dataDir}
	if err := AuthorizeCache(
		cfg,
		"user@example.com",
		accountID,
		vault.PasswordEnvelope,
	); err != nil {
		t.Fatal(err)
	}

	command := exec.Command(
		os.Args[0],
		"-test.run=TestCacheWriterProcess$",
	)
	command.Env = append(
		os.Environ(),
		"TERMKEEP_TEST_CACHE_WRITER=1",
		"TERMKEEP_TEST_DATA_DIR="+dataDir,
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("cache writer process: %v\n%s", err, output)
	}

	cache, err := OpenCache(cfg, "user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	items, err := cache.Items()
	if err != nil {
		t.Fatal(err)
	}
	pending, err := cache.PendingMutations()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || len(pending) != 1 ||
		items[0].ItemID != pending[0].Item.ItemID {
		t.Fatalf(
			"process exit lost cache state: items=%+v pending=%+v",
			items,
			pending,
		)
	}
}

func TestCacheWriterProcess(t *testing.T) {
	if os.Getenv("TERMKEEP_TEST_CACHE_WRITER") != "1" {
		return
	}
	cache, err := OpenCache(
		Config{DataDir: os.Getenv("TERMKEEP_TEST_DATA_DIR")},
		"user@example.com",
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = cache.QueueMutation(EncryptedItem{
		ItemID:        "11111111-1111-4111-8111-111111111111",
		SchemaVersion: 1,
		Revision:      1,
		Envelope:      []byte("encrypted"),
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	os.Exit(0)
}
