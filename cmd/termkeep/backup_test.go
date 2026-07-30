package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/davicbtoliveira/TermKeep/internal/client"
	"github.com/davicbtoliveira/TermKeep/internal/session"
)

func TestBackupCreateAndRestoreQueuesEncryptedMutationOffline(t *testing.T) {
	accountID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	vault, err := client.NewVault([]byte("TermKeep#2026"), accountID)
	if err != nil {
		t.Fatal(err)
	}
	defer vault.Clear()
	sourceCfg := client.Config{
		DataDir: filepath.Join(t.TempDir(), "source-cache"),
	}
	if err := client.AuthorizeCache(
		sourceCfg,
		"user@example.com",
		accountID,
		vault.PasswordEnvelope,
	); err != nil {
		t.Fatal(err)
	}
	sourceCache, err := client.OpenCache(sourceCfg, "user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	item, err := client.EncryptLogin(
		vault.Key,
		accountID,
		client.LoginItem{
			ItemID:   "11111111-1111-4111-8111-111111111111",
			Name:     "Offline backup login",
			Username: "user@example.com",
			Password: "Offline-Backup-Sentinel",
			Favorite: true,
		},
		1,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sourceCache.QueueMutation(item, 0); err != nil {
		t.Fatal(err)
	}

	destinationCfg := client.Config{
		DataDir: filepath.Join(t.TempDir(), "destination-cache"),
	}
	if err := client.AuthorizeCache(
		destinationCfg,
		"user@example.com",
		accountID,
		vault.PasswordEnvelope,
	); err != nil {
		t.Fatal(err)
	}
	destinationCache, err := client.OpenCache(
		destinationCfg,
		"user@example.com",
	)
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

	backupPath := filepath.Join(t.TempDir(), "vault.tkb")
	var output bytes.Buffer
	if err := runBackupCreateAt(
		context.Background(),
		sourceCfg,
		socketPath,
		backupRequest{action: backupActionCreate, path: backupPath},
		[]byte("TermKeep#2026"),
		&output,
	); err == nil ||
		!strings.Contains(err.Error(), "differ from the master password") {
		t.Fatalf("master password reuse: %v", err)
	}
	if err := runBackupCreateAt(
		context.Background(),
		sourceCfg,
		socketPath,
		backupRequest{action: backupActionCreate, path: backupPath},
		[]byte("different backup password"),
		&output,
	); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Backup created") {
		t.Fatalf("create output: %s", output.String())
	}
	createdBackup, err := client.ReadPortableBackupFile(
		backupPath,
		[]byte("different backup password"),
	)
	if err != nil || createdBackup.FormatVersion != 2 ||
		len(createdBackup.Items) != 1 {
		t.Fatalf("created portable backup: %v %+v", err, createdBackup)
	}

	output.Reset()
	var stderr bytes.Buffer
	restoreRequest := backupRequest{
		action: backupActionRestore,
		path:   backupPath,
	}
	if err := runBackupRestoreAt(
		context.Background(),
		destinationCfg,
		socketPath,
		restoreRequest,
		[]byte("different backup password"),
		&output,
		&stderr,
	); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Portable backup restore preview") {
		t.Fatalf("preview output: %s", output.String())
	}
	snapshot, err := destinationCache.SyncSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Mutations) != 0 {
		t.Fatalf("preview queued mutations: %+v", snapshot.Mutations)
	}

	output.Reset()
	restoreRequest.confirm = true
	if err := runBackupRestoreAt(
		context.Background(),
		destinationCfg,
		socketPath,
		restoreRequest,
		[]byte("different backup password"),
		&output,
		&stderr,
	); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Restored locally: 1") {
		t.Fatalf("restore output: %s", output.String())
	}
	snapshot, err = destinationCache.SyncSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Mutations) != 1 {
		t.Fatalf("restore mutations: %+v", snapshot.Mutations)
	}
	opened, err := session.OpenNativeItem(
		context.Background(),
		socketPath,
		snapshot.Mutations[0].Item,
	)
	if err != nil {
		t.Fatal(err)
	}
	if opened.Login == nil ||
		opened.Login.Password != "Offline-Backup-Sentinel" ||
		!opened.Login.Favorite {
		t.Fatalf("restored login: %+v", opened)
	}
	output.Reset()
	if err := runBackupRestoreAt(
		context.Background(),
		destinationCfg,
		socketPath,
		restoreRequest,
		[]byte("different backup password"),
		&output,
		&stderr,
	); err != nil {
		t.Fatal(err)
	}
	snapshot, err = destinationCache.SyncSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Mutations) != 1 ||
		!strings.Contains(output.String(), "Restored locally: 0") {
		t.Fatalf("repeat restore was not idempotent: %s / %+v", output.String(), snapshot)
	}
}

func TestBackupRestoresToDifferentVaultWithAllNativeFields(t *testing.T) {
	sourceAccount := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	destinationAccount := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	sourceVault, err := client.NewVault([]byte("Source-master#2026"), sourceAccount)
	if err != nil {
		t.Fatal(err)
	}
	defer sourceVault.Clear()
	destinationVault, err := client.NewVault([]byte("Destination-master#2026"), destinationAccount)
	if err != nil {
		t.Fatal(err)
	}
	defer destinationVault.Clear()
	sourceCfg := client.Config{DataDir: filepath.Join(t.TempDir(), "source-cache")}
	if err := client.AuthorizeCache(
		sourceCfg,
		"source@example.com",
		sourceAccount,
		sourceVault.PasswordEnvelope,
	); err != nil {
		t.Fatal(err)
	}
	sourceCache, err := client.OpenCache(sourceCfg, "source@example.com")
	if err != nil {
		t.Fatal(err)
	}
	totp, err := client.NewTOTPConfig(
		"JBSWY3DPEHPK3PXP",
		"Example",
		"source@example.com",
		"SHA256",
		8,
		60,
	)
	if err != nil {
		t.Fatal(err)
	}
	folder := client.FolderItem{
		ItemID: "11111111-1111-4111-8111-111111111111",
		Name:   "Portable folder",
	}
	login := client.LoginItem{
		ItemID:   "22222222-2222-4222-8222-222222222222",
		Name:     "Portable login",
		Username: "source@example.com",
		Password: "current-secret",
		FolderID: folder.ItemID,
		Favorite: true,
		PasswordHistory: []client.PasswordHistoryEntry{{
			Password:  "previous-secret",
			ChangedAt: time.Date(2026, 7, 30, 0, 0, 0, 0, time.UTC),
		}},
		TOTP: &totp,
	}
	note := client.SecureNoteItem{
		ItemID:   "33333333-3333-4333-8333-333333333333",
		Title:    "Portable note",
		Content:  "note content",
		FolderID: folder.ItemID,
		Favorite: true,
	}
	generic := client.GenericItem{
		ItemID:     "44444444-4444-4444-8444-444444444444",
		Title:      "Portable generic",
		Source:     "custom",
		SourceType: "json",
		FolderID:   folder.ItemID,
		Favorite:   true,
		Data:       []byte(`{"key":"value"}`),
	}
	items := []client.NativeItem{
		{Type: client.NativeItemTypeFolder, Folder: &folder},
		{Type: client.NativeItemTypeLogin, Login: &login},
		{Type: client.NativeItemTypeSecureNote, SecureNote: &note},
		{Type: client.NativeItemTypeGeneric, Generic: &generic},
	}
	for _, native := range items {
		var encrypted client.EncryptedItem
		switch native.Type {
		case client.NativeItemTypeFolder:
			encrypted, err = client.EncryptFolder(
				sourceVault.Key,
				sourceAccount,
				*native.Folder,
				1,
			)
		case client.NativeItemTypeLogin:
			encrypted, err = client.EncryptLogin(
				sourceVault.Key,
				sourceAccount,
				*native.Login,
				1,
			)
		case client.NativeItemTypeSecureNote:
			encrypted, err = client.EncryptSecureNote(
				sourceVault.Key,
				sourceAccount,
				*native.SecureNote,
				1,
			)
		case client.NativeItemTypeGeneric:
			encrypted, err = client.EncryptGenericItem(
				sourceVault.Key,
				sourceAccount,
				*native.Generic,
				1,
			)
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sourceCache.QueueMutation(encrypted, 0); err != nil {
			t.Fatal(err)
		}
	}
	backupPath := filepath.Join(t.TempDir(), "portable.tkb")
	if err := sourceCache.WritePortableBackupFileWithItems(
		backupPath,
		[]byte("portable backup password"),
		items,
	); err != nil {
		t.Fatal(err)
	}

	destinationCfg := client.Config{DataDir: filepath.Join(t.TempDir(), "destination-cache")}
	if err := client.AuthorizeCache(
		destinationCfg,
		"destination@example.com",
		destinationAccount,
		destinationVault.PasswordEnvelope,
	); err != nil {
		t.Fatal(err)
	}
	destinationCache, err := client.OpenCache(
		destinationCfg,
		"destination@example.com",
	)
	if err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(t.TempDir(), "destination-agent.sock")
	agent, err := session.NewAgent(session.AgentConfig{
		SocketPath: socketPath,
		OwnerUID:   uint32(os.Getuid()),
		AccountID:  destinationAccount,
		Email:      "destination@example.com",
		VaultKey:   destinationVault.Key,
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

	var output, stderr bytes.Buffer
	request := backupRequest{
		action:  backupActionRestore,
		path:    backupPath,
		confirm: true,
	}
	if err := runBackupRestoreAt(
		context.Background(),
		destinationCfg,
		socketPath,
		request,
		[]byte("portable backup password"),
		&output,
		&stderr,
	); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Restored locally: 4") {
		t.Fatalf("restore output: %s", output.String())
	}
	snapshot, err := destinationCache.SyncSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Mutations) != 4 {
		t.Fatalf("restored mutation count: %+v", snapshot.Mutations)
	}
	var restoredFolder client.FolderItem
	var restoredLogin client.LoginItem
	var restoredNote client.SecureNoteItem
	var restoredGeneric client.GenericItem
	for _, mutation := range snapshot.Mutations {
		native, openErr := session.OpenNativeItem(
			context.Background(),
			socketPath,
			mutation.Item,
		)
		if openErr != nil {
			t.Fatal(openErr)
		}
		switch native.Type {
		case client.NativeItemTypeFolder:
			restoredFolder = *native.Folder
		case client.NativeItemTypeLogin:
			restoredLogin = *native.Login
		case client.NativeItemTypeSecureNote:
			restoredNote = *native.SecureNote
		case client.NativeItemTypeGeneric:
			restoredGeneric = *native.Generic
		}
	}
	if restoredLogin.Password != login.Password ||
		len(restoredLogin.PasswordHistory) != 1 ||
		restoredLogin.PasswordHistory[0].Password != "previous-secret" ||
		restoredLogin.TOTP == nil || restoredLogin.TOTP.Digits != 8 ||
		!restoredLogin.Favorite || restoredLogin.FolderID != restoredFolder.ItemID ||
		restoredNote.FolderID != restoredFolder.ItemID || !restoredNote.Favorite ||
		restoredGeneric.FolderID != restoredFolder.ItemID || !restoredGeneric.Favorite ||
		string(restoredGeneric.Data) != string(generic.Data) {
		t.Fatalf("portable fields were not restored: login=%+v note=%+v generic=%+v folder=%+v", restoredLogin, restoredNote, restoredGeneric, restoredFolder)
	}
	output.Reset()
	if err := runBackupRestoreAt(
		context.Background(),
		destinationCfg,
		socketPath,
		request,
		[]byte("portable backup password"),
		&output,
		&stderr,
	); err != nil {
		t.Fatal(err)
	}
	snapshot, err = destinationCache.SyncSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Mutations) != 4 ||
		!strings.Contains(output.String(), "Restored locally: 0") {
		t.Fatalf("cross-vault retry duplicated restore: %s / %+v", output.String(), snapshot)
	}
}
