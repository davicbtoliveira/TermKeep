package client

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"testing/quick"
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
	if len(items) != 1 || !reflect.DeepEqual(items[0], mutation.Item) {
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
		RevisionID:    "33333333-3333-4333-8333-333333333333",
		Envelope:      []byte("remote-encrypted"),
	}
	if err := cache.ApplySync(
		"7",
		[]string{mutation.MutationID},
		[]EncryptedItem{mutation.Item, remote},
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

func TestCachePreservesAndResolvesConcurrentRevisionHeads(t *testing.T) {
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

	const itemID = "11111111-1111-4111-8111-111111111111"
	rootID := "22222222-2222-4222-8222-222222222222"
	firstID := "33333333-3333-4333-8333-333333333333"
	secondID := "44444444-4444-4444-8444-444444444444"
	root := EncryptedItem{
		ItemID:        itemID,
		SchemaVersion: 1,
		Revision:      1,
		RevisionID:    rootID,
		Envelope:      []byte("root"),
	}
	first := EncryptedItem{
		ItemID:            itemID,
		SchemaVersion:     1,
		Revision:          2,
		RevisionID:        firstID,
		ParentRevisionIDs: []string{rootID},
		Envelope:          []byte("first"),
	}
	second := EncryptedItem{
		ItemID:            itemID,
		SchemaVersion:     1,
		Revision:          2,
		RevisionID:        secondID,
		ParentRevisionIDs: []string{rootID},
		Envelope:          []byte("second"),
	}
	if err := cache.ApplySync(
		"3", nil, []EncryptedItem{root, second, first},
	); err != nil {
		t.Fatal(err)
	}

	groups, err := cache.ItemHeads()
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || len(groups[0].Revisions) != 2 {
		t.Fatalf("conflict heads: want 2, got %+v", groups)
	}
	got := map[string]string{}
	for _, revision := range groups[0].Revisions {
		got[revision.RevisionID] = string(revision.Envelope)
	}
	if got[firstID] != "first" || got[secondID] != "second" {
		t.Fatalf("concurrent heads were not preserved: %+v", got)
	}

	resolutionID := "55555555-5555-4555-8555-555555555555"
	resolution := EncryptedItem{
		ItemID:            itemID,
		SchemaVersion:     1,
		Revision:          3,
		RevisionID:        resolutionID,
		ParentRevisionIDs: []string{firstID, secondID},
		Envelope:          []byte("resolved"),
	}
	mutation, err := cache.QueueMutation(resolution, 2)
	if err != nil {
		t.Fatal(err)
	}
	if mutation.MutationID != resolutionID {
		t.Fatalf("resolution mutation ID: want %s, got %s",
			resolutionID, mutation.MutationID)
	}
	groups, err = cache.ItemHeads()
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || len(groups[0].Revisions) != 1 ||
		groups[0].Revisions[0].RevisionID != resolutionID {
		t.Fatalf("resolved heads: %+v", groups)
	}
}

func TestCacheEditDescendsFromItsOnlyHead(t *testing.T) {
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
	root := EncryptedItem{
		ItemID:        "11111111-1111-4111-8111-111111111111",
		SchemaVersion: 1,
		Revision:      1,
		RevisionID:    "22222222-2222-4222-8222-222222222222",
		Envelope:      []byte("root"),
	}
	if err := cache.ApplySync("1", nil, []EncryptedItem{root}); err != nil {
		t.Fatal(err)
	}
	mutation, err := cache.QueueMutation(EncryptedItem{
		ItemID:        root.ItemID,
		SchemaVersion: 1,
		Revision:      2,
		Envelope:      []byte("edited"),
	}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(mutation.Item.ParentRevisionIDs) != 1 ||
		mutation.Item.ParentRevisionIDs[0] != root.RevisionID {
		t.Fatalf("edit parents: %+v", mutation.Item.ParentRevisionIDs)
	}
}

func TestLegacyCacheMigratesPendingMutationToRevisionDAG(t *testing.T) {
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
		Revision:      2,
		Envelope:      []byte("legacy-pending"),
	}
	mutationID := "22222222-2222-4222-8222-222222222222"
	legacy, err := json.Marshal(cacheFile{
		Version:               legacyCacheFormatVersion,
		AccountID:             accountID,
		Email:                 "user@example.com",
		PasswordVaultEnvelope: vault.PasswordEnvelope,
		Items: map[string]EncryptedItem{
			item.ItemID: item,
		},
		Mutations: []Mutation{{
			MutationID:   mutationID,
			BaseRevision: 1,
			Item:         item,
		}},
		Cursor: "1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cache.Path(), legacy, 0o600); err != nil {
		t.Fatal(err)
	}

	migrated, err := OpenCache(cfg, "user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	pending, err := migrated.PendingMutations()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 ||
		pending[0].Item.RevisionID != mutationID ||
		len(pending[0].Item.ParentRevisionIDs) != 1 ||
		pending[0].Item.ParentRevisionIDs[0] !=
			legacyRevisionID(accountID, item.ItemID, 1) {
		t.Fatalf("migrated mutation: %+v", pending)
	}
	groups, err := migrated.ItemHeads()
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || len(groups[0].Revisions) != 1 ||
		groups[0].Revisions[0].RevisionID != mutationID {
		t.Fatalf("migrated heads: %+v", groups)
	}
}

func TestPropertyPushPullOrdersPreserveConcurrentRevisions(t *testing.T) {
	password := []byte("TermKeep#2026")
	accountID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	vault, err := NewVault(password, accountID)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Clear()

	const (
		itemID   = "11111111-1111-4111-8111-111111111111"
		rootID   = "22222222-2222-4222-8222-222222222222"
		firstID  = "33333333-3333-4333-8333-333333333333"
		secondID = "44444444-4444-4444-8444-444444444444"
	)
	root := EncryptedItem{
		ItemID:        itemID,
		SchemaVersion: 1,
		Revision:      1,
		RevisionID:    rootID,
		Envelope:      []byte("root"),
	}
	first := EncryptedItem{
		ItemID:            itemID,
		SchemaVersion:     1,
		Revision:          2,
		RevisionID:        firstID,
		ParentRevisionIDs: []string{rootID},
		Envelope:          []byte("first"),
	}
	second := EncryptedItem{
		ItemID:            itemID,
		SchemaVersion:     1,
		Revision:          2,
		RevisionID:        secondID,
		ParentRevisionIDs: []string{rootID},
		Envelope:          []byte("second"),
	}
	property := func(order uint8) bool {
		cfg := Config{DataDir: filepath.Join(t.TempDir(), "cache")}
		if err := AuthorizeCache(
			cfg,
			"user@example.com",
			accountID,
			vault.PasswordEnvelope,
		); err != nil {
			return false
		}
		cache, err := OpenCache(cfg, "user@example.com")
		if err != nil {
			return false
		}
		if err := cache.ApplySync(
			"1", nil, []EncryptedItem{root},
		); err != nil {
			return false
		}
		mutation, err := cache.QueueMutation(first, 1)
		if err != nil {
			return false
		}

		if order%2 == 0 {
			if err := cache.ApplySync(
				"2",
				[]string{mutation.MutationID},
				[]EncryptedItem{first},
			); err != nil {
				return false
			}
			if err := cache.ApplySync(
				"3", nil, []EncryptedItem{second},
			); err != nil {
				return false
			}
		} else {
			if err := cache.ApplySync(
				"2", nil, []EncryptedItem{second},
			); err != nil {
				return false
			}
			changes := []EncryptedItem{first, second}
			if order&2 != 0 {
				changes[0], changes[1] = changes[1], changes[0]
			}
			if err := cache.ApplySync(
				"3",
				[]string{mutation.MutationID},
				changes,
			); err != nil {
				return false
			}
		}
		if order&4 != 0 {
			if err := cache.ApplySync(
				"3", nil, []EncryptedItem{second, first},
			); err != nil {
				return false
			}
		}

		groups, err := cache.ItemHeads()
		if err != nil || len(groups) != 1 ||
			len(groups[0].Revisions) != 2 {
			return false
		}
		got := map[string]bool{}
		for _, revision := range groups[0].Revisions {
			got[revision.RevisionID] = true
		}
		snapshot, err := cache.SyncSnapshot()
		return err == nil &&
			snapshot.Cursor == "3" &&
			len(snapshot.Mutations) == 0 &&
			got[firstID] &&
			got[secondID]
	}
	if err := quick.Check(property, &quick.Config{MaxCount: 32}); err != nil {
		t.Fatal(err)
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
