package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func TestTOTPRequestRequiresExplicitStdoutFlag(t *testing.T) {
	_, err := parseTOTPRequest([]string{
		"--item", "11111111-1111-4111-8111-111111111111",
	})
	if !errors.Is(err, errTOTPUsage) {
		t.Fatalf("missing --stdout error: got %v", err)
	}

	request, err := parseTOTPRequest([]string{
		"--item", "11111111-1111-4111-8111-111111111111",
		"--stdout",
	})
	if err != nil {
		t.Fatal(err)
	}
	if request.itemID != "11111111-1111-4111-8111-111111111111" {
		t.Fatalf("TOTP request: %+v", request)
	}
}

func TestPasswordGeneratorRequestRequiresExplicitValidOutput(t *testing.T) {
	_, err := parsePasswordGeneratorRequest([]string{
		"--length", "32",
	})
	if !errors.Is(err, errPasswordGeneratorUsage) {
		t.Fatalf("missing --stdout error: got %v", err)
	}
	_, err = parsePasswordGeneratorRequest([]string{
		"--length", "4",
		"--stdout",
	})
	if !errors.Is(err, errPasswordGeneratorUsage) {
		t.Fatalf("invalid config error: got %v", err)
	}

	request, err := parsePasswordGeneratorRequest([]string{
		"--length", "32",
		"--uppercase=true",
		"--lowercase=true",
		"--digits=true",
		"--special=false",
		"--min-digits", "4",
		"--min-special", "0",
		"--exclude-ambiguous",
		"--stdout",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := client.PasswordGeneratorConfig{
		Length:           32,
		Uppercase:        true,
		Lowercase:        true,
		Digits:           true,
		Special:          false,
		MinimumDigits:    4,
		MinimumSpecial:   0,
		ExcludeAmbiguous: true,
	}
	if request.config != want {
		t.Fatalf(
			"generator config:\nwant: %+v\ngot:  %+v",
			want,
			request.config,
		)
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

func TestTOTPCommandWritesCurrentCodeFromUnlockedCache(t *testing.T) {
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
			ItemID: itemID,
			Name:   "Production database",
			TOTP: &client.TOTPConfig{
				Secret:    "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
				Algorithm: client.TOTPAlgorithmSHA1,
				Digits:    6,
				Period:    30,
			},
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
	err = outputTOTPAt(
		context.Background(),
		cfg,
		socketPath,
		totpRequest{itemID: itemID},
		time.Unix(59, 0),
		&stdout,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := stdout.String(); got != "287082\n" {
		t.Fatalf("TOTP stdout: got %q", got)
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

func TestAccountCreationRequiresExplicitRecoveryKeyStdoutFlag(t *testing.T) {
	for _, test := range []struct {
		name string
		run  func() int
	}{
		{
			name: "bootstrap",
			run: func() int {
				return runBootstrap(client.Config{}, []string{
					"--email", "admin@example.com",
				})
			},
		},
		{
			name: "register",
			run: func() int {
				return runRegister(client.Config{}, []string{
					"--email", "user@example.com",
					"--invite-token", "invite-token",
				})
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			stderr := captureStderr(t, test.run)
			if !strings.Contains(stderr, "--stdout-recovery-key") {
				t.Fatalf("usage omitted explicit flag:\n%s", stderr)
			}
			if strings.Contains(stderr, "Master password:") {
				t.Fatalf("command prompted before explicit flag:\n%s", stderr)
			}
		})
	}
}

func captureStderr(t *testing.T, run func() int) string {
	t.Helper()
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stderr
	os.Stderr = write
	defer func() { os.Stderr = original }()
	code := run()
	if err := write.Close(); err != nil {
		t.Fatal(err)
	}
	output, err := io.ReadAll(read)
	if err != nil {
		t.Fatal(err)
	}
	if err := read.Close(); err != nil {
		t.Fatal(err)
	}
	if code != exitUsageFailure {
		t.Fatalf("exit code: got %d, want %d", code, exitUsageFailure)
	}
	return string(output)
}
