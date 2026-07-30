package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

func TestGlobalConfiguresPwnedPasswordsEndpoint(t *testing.T) {
	t.Setenv(
		"TERMKEEP_PWNED_PASSWORDS_URL",
		"https://pwned.internal/range",
	)
	cfg, args, err := parseGlobalConfig([]string{"status"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PwnedPasswordsURL != "https://pwned.internal/range" ||
		len(args) != 1 ||
		args[0] != "status" {
		t.Fatalf("environment config: cfg=%+v args=%v", cfg, args)
	}

	cfg, args, err = parseGlobalConfig([]string{
		"--pwned-passwords-url",
		"off",
		"status",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PwnedPasswordsURL != "off" ||
		len(args) != 1 ||
		args[0] != "status" {
		t.Fatalf("flag config: cfg=%+v args=%v", cfg, args)
	}

	t.Setenv("TERMKEEP_PWNED_PASSWORDS_URL", "")
	cfg, _, err = parseGlobalConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PwnedPasswordsURL != client.DefaultPwnedPasswordsURL {
		t.Fatalf("default endpoint: %q", cfg.PwnedPasswordsURL)
	}
}

func TestBackupRequestRequiresActionAndFile(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"create"},
		{"restore", "--file", "backup.tkb", "--unknown"},
		{"unknown", "--file", "backup.tkb"},
		{"create", "--file", "backup.tkb", "--confirm"},
	} {
		if _, err := parseBackupRequest(args); !errors.Is(
			err,
			errBackupUsage,
		) {
			t.Fatalf("args %v: got %v", args, err)
		}
	}
	create, err := parseBackupRequest([]string{
		"create", "--file", "/tmp/backup.tkb",
	})
	if err != nil {
		t.Fatal(err)
	}
	if create.action != backupActionCreate ||
		create.path != "/tmp/backup.tkb" || create.confirm {
		t.Fatalf("create request: %+v", create)
	}
	restore, err := parseBackupRequest([]string{
		"restore", "--file", "/tmp/backup.tkb", "--confirm",
	})
	if err != nil {
		t.Fatal(err)
	}
	if restore.action != backupActionRestore ||
		restore.path != "/tmp/backup.tkb" || !restore.confirm {
		t.Fatalf("restore request: %+v", restore)
	}
}

func TestImportRequestRequiresSupportedFormatAndFile(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"bitwarden"},
		{"1password"},
		{"csv"},
		{"unknown", "--file", "vault.json"},
	} {
		if _, err := parseImportRequest(args); !errors.Is(
			err,
			errImportUsage,
		) {
			t.Fatalf("args %v: got %v", args, err)
		}
	}

	tests := []struct {
		format importFormat
		path   string
	}{
		{
			format: importFormatBitwarden,
			path:   "/tmp/bitwarden.json",
		},
		{
			format: importFormatOnePassword,
			path:   "/tmp/account.1pux",
		},
	}
	for _, test := range tests {
		request, err := parseImportRequest([]string{
			string(test.format),
			"--file",
			test.path,
			"--confirm",
		})
		if err != nil {
			t.Fatal(err)
		}
		if request.format != test.format ||
			request.path != test.path ||
			!request.confirm {
			t.Fatalf("import request: %+v", request)
		}
	}

	request, err := parseImportRequest([]string{
		"csv",
		"--file",
		"/tmp/account.csv",
	})
	if err != nil {
		t.Fatal(err)
	}
	if request.format != importFormatCSV ||
		request.path != "/tmp/account.csv" ||
		request.confirm {
		t.Fatalf("CSV inspection request: %+v", request)
	}
}

func TestCSVImportRequestRequiresExplicitMappingDecisions(t *testing.T) {
	request, err := parseImportRequest([]string{
		"csv",
		"--file", "/tmp/account.csv",
		"--type", "login",
		"--map", "name=Title",
		"--map", "username=User",
		"--ignore", "Legacy ID",
		"--delimiter", "semicolon",
		"--encoding", "utf-8",
		"--confirm",
	})
	if err != nil {
		t.Fatal(err)
	}
	if request.csv.Type != client.NativeItemTypeLogin ||
		request.csv.Mapping["name"] != "Title" ||
		request.csv.Mapping["username"] != "User" ||
		len(request.csv.IgnoredColumns) != 1 ||
		request.csv.IgnoredColumns[0] != "Legacy ID" ||
		request.csv.Delimiter != ';' ||
		request.csv.Encoding != "utf-8" ||
		!request.confirm {
		t.Fatalf("CSV import request: %+v", request)
	}
}

func TestExportRequestRequiresExplicitFormatAndDestination(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"--file", "vault.json"},
		{"xml", "--file", "vault.xml"},
		{"json"},
		{"csv", "--file", "vault.csv", "--type", "unknown"},
		{"json", "--file", "vault.json", "--type", "login"},
	} {
		if _, err := parseExportRequest(args); !errors.Is(
			err,
			errExportUsage,
		) {
			t.Fatalf("args %v: got %v", args, err)
		}
	}
	request, err := parseExportRequest([]string{
		"csv", "--file", "/tmp/vault.csv", "--type", "generic",
		"--delimiter", "semicolon", "--confirm-plaintext",
	})
	if err != nil {
		t.Fatal(err)
	}
	if request.format != exportFormatCSV || request.path != "/tmp/vault.csv" ||
		request.csvType != client.NativeItemTypeGeneric ||
		request.delimiter != ';' || !request.confirm {
		t.Fatalf("export request: %+v", request)
	}
}

func TestPlaintextExportPreviewsAndWritesLocally(t *testing.T) {
	accountID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	vault, err := client.NewVault([]byte("TermKeep#2026"), accountID)
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
	login := client.LoginItem{
		ItemID:   "11111111-1111-4111-8111-111111111111",
		Name:     "Export sentinel",
		Username: "export@example.com",
		Password: "Export-password-sentinel",
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
	encrypted, err := session.SealLogin(context.Background(), socketPath, login, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cache.QueueMutation(encrypted, 0); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "vault.json")
	if err := os.WriteFile(path, []byte("previous"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	request := exportRequest{format: exportFormatJSON, path: path}
	if err := runExportAt(
		context.Background(), cfg, socketPath, request, &stdout, &stderr,
	); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "Preview only") ||
		!strings.Contains(stderr.String(), "plaintext") ||
		strings.Contains(stdout.String(), login.Password) ||
		strings.Contains(stderr.String(), login.Password) {
		t.Fatalf("export preview leaked or failed:\nstdout=%s\nstderr=%s",
			stdout.String(), stderr.String())
	}
	unchanged, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(unchanged) != "previous" {
		t.Fatalf("preview changed destination: %q", unchanged)
	}
	stdout.Reset()
	stderr.Reset()
	request.confirm = true
	if err := runExportAt(
		context.Background(), cfg, socketPath, request, &stdout, &stderr,
	); err != nil {
		t.Fatal(err)
	}
	items, err := client.ReadJSONExportFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Login == nil ||
		items[0].Login.Password != login.Password {
		t.Fatalf("exported items: %+v", items)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("export mode = %o", info.Mode().Perm())
	}
	if strings.Contains(stdout.String(), login.Password) ||
		strings.Contains(stderr.String(), login.Password) {
		t.Fatalf("confirmed export logged plaintext:\nstdout=%s\nstderr=%s",
			stdout.String(), stderr.String())
	}
}

func TestBitwardenImportPreviewAndExplicitConfirmation(t *testing.T) {
	testImportPreviewAndExplicitConfirmation(
		t,
		importFormatBitwarden,
		"bitwarden.json",
		[]byte(`{
			"encrypted": false,
			"folders": [],
			"items": [{
				"type": 1,
				"name": "Imported account",
				"login": {
					"username": "imported@example.com",
					"password": "Imported-Password-Sentinel"
				}
			}]
		}`),
		1,
		client.LoginItem{
			Name:     "Imported account",
			Username: "imported@example.com",
			Password: "Imported-Password-Sentinel",
		},
	)
}

func TestOnePasswordImportPreviewAndExplicitConfirmation(t *testing.T) {
	source, err := os.ReadFile(
		"../../internal/client/testdata/onepassword-export.1pux",
	)
	if err != nil {
		t.Fatal(err)
	}
	testImportPreviewAndExplicitConfirmation(
		t,
		importFormatOnePassword,
		"account.1pux",
		source,
		4,
		client.LoginItem{
			Name:     "Production database",
			Username: "operator@example.com",
			Password: "Current-Password-Sentinel",
		},
	)
}

func TestCSVImportPreviewAndExplicitConfirmation(t *testing.T) {
	testImportPreviewAndExplicitConfirmation(
		t,
		importFormatCSV,
		"account.csv",
		[]byte(
			"Title,User,Password,Ignored\n"+
				"Imported CSV,imported@example.com,"+
				"CSV-Password-Sentinel,legacy\n",
		),
		1,
		client.LoginItem{
			Name:     "Imported CSV",
			Username: "imported@example.com",
			Password: "CSV-Password-Sentinel",
		},
	)
}

func testImportPreviewAndExplicitConfirmation(
	t *testing.T,
	format importFormat,
	fileName string,
	source []byte,
	expectedItems int,
	expectedLogin client.LoginItem,
) {
	t.Helper()
	accountID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	vault, err := client.NewVault([]byte("TermKeep#2026"), accountID)
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
	var (
		syncRequests int
		syncBody     []byte
		synced       []client.Mutation
	)
	server := httptest.NewServer(http.HandlerFunc(func(
		w http.ResponseWriter,
		r *http.Request,
	) {
		syncRequests++
		syncBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		var request struct {
			Mutations []client.Mutation `json:"mutations"`
		}
		if err := json.Unmarshal(syncBody, &request); err != nil {
			t.Fatal(err)
		}
		synced = request.Mutations
		applied := make([]string, 0, len(synced))
		changes := make([]client.EncryptedItem, 0, len(synced))
		for _, mutation := range synced {
			applied = append(applied, mutation.MutationID)
			changes = append(changes, mutation.Item)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"cursor":               "1",
			"applied_mutation_ids": applied,
			"changes":              changes,
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
	path := filepath.Join(t.TempDir(), fileName)
	if err := os.WriteFile(path, source, 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	request := importRequest{format: format, path: path}
	if format == importFormatCSV {
		request.csv = client.CSVImportOptions{
			Type: client.NativeItemTypeLogin,
			Mapping: map[string]string{
				"name":     "Title",
				"username": "User",
				"password": "Password",
			},
			IgnoredColumns: []string{"Ignored"},
		}
	}
	if err := runImportAt(
		context.Background(),
		cfg,
		socketPath,
		request,
		&stdout,
		&stderr,
	); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "Logins: 1") ||
		!strings.Contains(stdout.String(), "Preview only") ||
		strings.Count(stderr.String(), "plaintext") !=
			expectedPlaintextWarnings(format) {
		t.Fatalf("preview output:\nstdout=%s\nstderr=%s",
			stdout.String(), stderr.String())
	}
	snapshot, err := cache.SyncSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Mutations) != 0 || syncRequests != 0 {
		t.Fatalf("preview queued mutations: %+v", snapshot)
	}

	stdout.Reset()
	stderr.Reset()
	request.confirm = true
	if err := runImportAt(
		context.Background(),
		cfg,
		socketPath,
		request,
		&stdout,
		&stderr,
	); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(
		stdout.String(),
		fmt.Sprintf("Imported locally: %d", expectedItems),
	) || strings.Count(stderr.String(), "plaintext") !=
		expectedPlaintextWarnings(format) {
		t.Fatalf("confirmation output:\n%s", stdout.String())
	}
	snapshot, err = cache.SyncSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Mutations) != 0 ||
		syncRequests != 1 ||
		len(synced) != expectedItems {
		t.Fatalf(
			"confirmation sync: snapshot=%+v requests=%d mutations=%+v",
			snapshot,
			syncRequests,
			synced,
		)
	}
	for _, forbidden := range []string{
		expectedLogin.Name,
		expectedLogin.Username,
		expectedLogin.Password,
	} {
		if bytes.Contains(syncBody, []byte(forbidden)) {
			t.Fatalf("synchronization request exposed %q", forbidden)
		}
	}
	var openedLogin *client.LoginItem
	for _, mutation := range synced {
		opened, err := session.OpenNativeItem(
			context.Background(),
			socketPath,
			mutation.Item,
		)
		if err != nil {
			t.Fatal(err)
		}
		if opened.Login != nil {
			openedLogin = opened.Login
			break
		}
	}
	if openedLogin == nil ||
		openedLogin.Name != expectedLogin.Name ||
		openedLogin.Username != expectedLogin.Username ||
		openedLogin.Password != expectedLogin.Password {
		t.Fatalf("confirmed Login differs: %+v", openedLogin)
	}
}

func expectedPlaintextWarnings(format importFormat) int {
	if format == importFormatCSV {
		return 2
	}
	return 1
}

func TestCSVImportWithInvalidRowQueuesNothing(t *testing.T) {
	accountID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	vault, err := client.NewVault([]byte("TermKeep#2026"), accountID)
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
	path := filepath.Join(t.TempDir(), "invalid.csv")
	if err := os.WriteFile(
		path,
		[]byte("Title,User\nValid,user@example.com\nBroken\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	err = runImportAt(
		context.Background(),
		cfg,
		socketPath,
		importRequest{
			format:  importFormatCSV,
			path:    path,
			confirm: true,
			csv: client.CSVImportOptions{
				Type: client.NativeItemTypeLogin,
				Mapping: map[string]string{
					"name":     "Title",
					"username": "User",
				},
			},
		},
		&stdout,
		&stderr,
	)
	if err == nil ||
		!strings.Contains(err.Error(), "preview contains errors") ||
		!strings.Contains(stdout.String(), "Error Item 2") ||
		strings.Count(stderr.String(), "plaintext") != 2 {
		t.Fatalf(
			"error=%v\nstdout=%s\nstderr=%s",
			err,
			stdout.String(),
			stderr.String(),
		)
	}
	snapshot, err := cache.SyncSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Mutations) != 0 {
		t.Fatalf("invalid CSV queued mutations: %+v", snapshot.Mutations)
	}
}

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

func TestPasswordGeneratorCommandWritesConstrainedPassword(t *testing.T) {
	config := client.PasswordGeneratorConfig{
		Length:           48,
		Uppercase:        true,
		Lowercase:        true,
		Digits:           true,
		MinimumDigits:    8,
		ExcludeAmbiguous: true,
	}
	var stdout bytes.Buffer
	if err := outputGeneratedPassword(config, &stdout); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(stdout.String(), "\n") {
		t.Fatalf("password output lacks newline: %q", stdout.String())
	}
	password := strings.TrimSuffix(stdout.String(), "\n")
	if len(password) != config.Length {
		t.Fatalf("length: want %d, got %d", config.Length, len(password))
	}
	var digits int
	allowed := client.PasswordUppercaseCharacters +
		client.PasswordLowercaseCharacters +
		client.PasswordDigits
	for _, character := range password {
		if !strings.ContainsRune(allowed, character) {
			t.Fatalf("disallowed output character %q", character)
		}
		if strings.ContainsRune(client.PasswordDigits, character) {
			digits++
		}
	}
	if digits < config.MinimumDigits {
		t.Fatalf("minimum digits not met: %q", password)
	}
	if strings.ContainsAny(
		password,
		client.PasswordAmbiguousCharacters,
	) {
		t.Fatalf("ambiguous character in output: %q", password)
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
