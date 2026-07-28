package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestSyncCachePushesPendingMutationAndAppliesResponse(t *testing.T) {
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

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost ||
			r.URL.Path != "/api/v1/sync" ||
			r.Header.Get("Authorization") != "Bearer access-token" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		var request struct {
			Cursor    string     `json:"cursor"`
			Mutations []Mutation `json:"mutations"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if request.Cursor != "" ||
			len(request.Mutations) != 1 ||
			request.Mutations[0].MutationID != mutation.MutationID {
			t.Fatalf("unexpected synchronization request: %+v", request)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"cursor":               "1",
			"applied_mutation_ids": []string{mutation.MutationID},
			"changes":              []EncryptedItem{item},
		})
	}))
	defer server.Close()
	cfg.ServerURL = server.URL

	if err := SyncCache(
		context.Background(), cfg, "access-token", cache,
	); err != nil {
		t.Fatal(err)
	}
	snapshot, err := cache.SyncSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Cursor != "1" || len(snapshot.Mutations) != 0 {
		t.Fatalf("synchronization response not applied: %+v", snapshot)
	}
}
