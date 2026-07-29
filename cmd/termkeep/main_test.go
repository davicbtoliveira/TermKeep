package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/davicbtoliveira/TermKeep/internal/client"
	"github.com/davicbtoliveira/TermKeep/internal/session"
)

func TestManualSyncUsesActiveSessionAndCache(t *testing.T) {
	accountID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	password := []byte("TermKeep#2026")
	vault, err := client.NewVault(password, accountID)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Clear()
	cfg := client.Config{DataDir: filepath.Join(t.TempDir(), "cache")}
	if err := client.AuthorizeCache(
		cfg,
		"user@example.com",
		accountID,
		vault.PasswordEnvelope,
	); err != nil {
		t.Fatal(err)
	}
	cache, err := client.OpenCache(cfg, "user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	item := client.EncryptedItem{
		ItemID:        "11111111-1111-4111-8111-111111111111",
		SchemaVersion: 1,
		Revision:      1,
		Envelope:      []byte("encrypted"),
	}
	mutation, err := cache.QueueMutation(item, 0)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(
		w http.ResponseWriter,
		_ *http.Request,
	) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"cursor":               "1",
			"applied_mutation_ids": []string{mutation.MutationID},
			"changes":              []client.EncryptedItem{mutation.Item},
		})
	}))
	defer server.Close()
	cfg.ServerURL = server.URL

	socketPath := filepath.Join(t.TempDir(), "agent.sock")
	agent, err := session.NewAgent(session.AgentConfig{
		SocketPath:  socketPath,
		OwnerUID:    uint32(os.Getuid()),
		AccountID:   accountID,
		Email:       "user@example.com",
		VaultKey:    vault.Key,
		AccessToken: []byte("access-token"),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- agent.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = agent.Close()
		if err := <-done; err != nil {
			t.Errorf("serve agent: %v", err)
		}
	})

	if code := runSyncAt(cfg, socketPath); code != 0 {
		t.Fatalf("manual sync exit: want 0, got %d", code)
	}
	snapshot, err := cache.SyncSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Mutations) != 0 {
		t.Fatalf("manual sync left pending mutations: %+v", snapshot)
	}
}

func TestSecretRequestRequiresExplicitStdoutFlag(t *testing.T) {
	_, err := parseSecretRequest([]string{
		"--item", "11111111-1111-4111-8111-111111111111",
		"--field", "password",
	})
	if !errors.Is(err, errSecretUsage) {
		t.Fatalf("missing --stdout error: got %v", err)
	}

	request, err := parseSecretRequest([]string{
		"--item", "11111111-1111-4111-8111-111111111111",
		"--field", "password",
		"--stdout",
	})
	if err != nil {
		t.Fatal(err)
	}
	if request.itemID != "11111111-1111-4111-8111-111111111111" ||
		request.field != "password" {
		t.Fatalf("secret request: %+v", request)
	}
}

func TestSecretCommandWritesRequestedPassword(t *testing.T) {
	accountID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	itemID := "11111111-1111-4111-8111-111111111111"
	password := []byte("TermKeep#2026")
	vault, err := client.NewVault(password, accountID)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Clear()
	cfg := client.Config{DataDir: filepath.Join(t.TempDir(), "cache")}
	if err := client.AuthorizeCache(
		cfg,
		"user@example.com",
		accountID,
		vault.PasswordEnvelope,
	); err != nil {
		t.Fatal(err)
	}
	cache, err := client.OpenCache(cfg, "user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	item, err := client.EncryptLogin(
		vault.Key,
		accountID,
		client.LoginItem{
			ItemID:   itemID,
			Name:     "Production database",
			Password: "Password-Sentinel",
		},
		1,
	)
	if err != nil {
		t.Fatal(err)
	}
	item.RevisionID = "22222222-2222-4222-8222-222222222222"
	if _, err := cache.QueueMutation(item, 0); err != nil {
		t.Fatal(err)
	}

	socketPath := filepath.Join(t.TempDir(), "agent.sock")
	agent, err := session.NewAgent(session.AgentConfig{
		SocketPath: socketPath,
		OwnerUID:   uint32(os.Getuid()),
		AccountID:  accountID,
		Email:      "user@example.com",
		VaultKey:   vault.Key,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- agent.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = agent.Close()
		if err := <-done; err != nil {
			t.Errorf("serve agent: %v", err)
		}
	})

	var stdout bytes.Buffer
	err = outputSecretAt(
		context.Background(),
		cfg,
		socketPath,
		secretRequest{itemID: itemID, field: "password"},
		&stdout,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := stdout.String(); got != "Password-Sentinel\n" {
		t.Fatalf("secret stdout: got %q", got)
	}
}

func TestRequestedSecretSupportsExplicitNativeFields(t *testing.T) {
	login := client.NativeItem{
		Type: client.NativeItemTypeLogin,
		Login: &client.LoginItem{
			Password: "Password-Sentinel",
			Notes:    "Login-Notes-Sentinel",
			CustomFields: []client.CustomField{{
				Name:  "API token",
				Value: "Custom-Value-Sentinel",
			}},
		},
	}
	note := client.NativeItem{
		Type: client.NativeItemTypeSecureNote,
		SecureNote: &client.SecureNoteItem{
			Content: "Secure-Note-Content-Sentinel",
		},
	}
	for _, test := range []struct {
		name  string
		item  client.NativeItem
		field string
		want  string
	}{
		{
			name: "Login notes", item: login,
			field: "notes", want: "Login-Notes-Sentinel",
		},
		{
			name: "custom field", item: login,
			field: "custom:API token", want: "Custom-Value-Sentinel",
		},
		{
			name: "Secure Note content", item: note,
			field: "content", want: "Secure-Note-Content-Sentinel",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := requestedSecret(test.item, test.field)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("secret: got %q, want %q", got, test.want)
			}
		})
	}
}
