package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestPortableBackupRoundTripAuthenticatesEncryptedCache(t *testing.T) {
	accountID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	vault, err := NewVault([]byte("TermKeep#2026"), accountID)
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
	item, err := EncryptLogin(
		vault.Key,
		accountID,
		LoginItem{
			ItemID:   "11111111-1111-4111-8111-111111111111",
			Name:     "Backup account",
			Password: "Backup-Password-Sentinel",
		},
		1,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cache.QueueMutation(item, 0); err != nil {
		t.Fatal(err)
	}

	backupPassword := []byte("separate backup password")
	var encoded bytes.Buffer
	if err := cache.WritePortableBackup(&encoded, backupPassword); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded.Bytes(), []byte("Backup-Password-Sentinel")) {
		t.Fatal("backup contains semantic plaintext")
	}
	backup, err := ReadPortableBackup(
		bytes.NewReader(encoded.Bytes()),
		backupPassword,
	)
	if err != nil {
		t.Fatal(err)
	}
	if backup.FormatVersion != portableBackupLegacyVersion ||
		backup.AccountID != accountID ||
		backup.Email != "user@example.com" ||
		len(backup.Revisions[item.ItemID]) != 1 ||
		len(backup.Mutations) != 1 {
		t.Fatalf("backup metadata: %+v", backup)
	}
	var portableEncoded bytes.Buffer
	if err := cache.WritePortableBackupWithItems(
		&portableEncoded,
		backupPassword,
		[]NativeItem{{
			Type: NativeItemTypeLogin,
			Login: &LoginItem{
				ItemID:   item.ItemID,
				Name:     "Backup account",
				Password: "Backup-Password-Sentinel",
			},
		}},
	); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(
		portableEncoded.Bytes(),
		[]byte("Backup-Password-Sentinel"),
	) {
		t.Fatal("portable backup contains semantic plaintext")
	}
	portable, err := ReadPortableBackup(
		bytes.NewReader(portableEncoded.Bytes()),
		backupPassword,
	)
	if err != nil || portable.FormatVersion != portableBackupFormatVersion ||
		len(portable.Items) != 1 {
		t.Fatalf("portable backup version/items: %v %+v", err, portable)
	}

	for name, source := range map[string][]byte{
		"wrong password": encoded.Bytes(),
		"truncated":      encoded.Bytes()[:len(encoded.Bytes())/2],
		"trailing bytes": append(append([]byte(nil), encoded.Bytes()...), '\n'),
		"tampered": func() []byte {
			value := append([]byte(nil), encoded.Bytes()...)
			value[len(value)-1] ^= 1
			return value
		}(),
	} {
		password := backupPassword
		if name == "wrong password" {
			password = []byte("wrong backup password")
		}
		if _, err := ReadPortableBackup(
			bytes.NewReader(source),
			password,
		); err == nil || !errors.Is(err, ErrInvalidPortableBackup) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

func TestPortableBackupRejectsEmptyPassword(t *testing.T) {
	cfg := Config{DataDir: filepath.Join(t.TempDir(), "cache")}
	if err := AuthorizeCache(
		cfg,
		"user@example.com",
		"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		[]byte("envelope"),
	); err != nil {
		t.Fatal(err)
	}
	cache, err := OpenCache(cfg, "user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := cache.WritePortableBackup(&output, nil); err == nil ||
		!strings.Contains(err.Error(), "backup password") {
		t.Fatalf("got %v", err)
	}
}

func TestPortableBackupRejectsUnsupportedVersionBeforeDecrypting(t *testing.T) {
	_, err := ReadPortableBackup(
		strings.NewReader(`{"magic":"termkeep-portable-backup","version":99}`),
		[]byte("backup password"),
	)
	if !errors.Is(err, ErrInvalidPortableBackup) {
		t.Fatalf("got %v", err)
	}
}

func TestPortableBackupCompatibilityVector(t *testing.T) {
	password := []byte("compatibility backup password")
	payload, err := json.Marshal(portableBackupPayload{
		Version:   portableBackupLegacyVersion,
		AccountID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		Email:     "user@example.com",
		Envelope:  []byte("password-envelope"),
		Revisions: map[string]map[string]EncryptedItem{
			"11111111-1111-4111-8111-111111111111": {
				"22222222-2222-4222-8222-222222222222": {
					ItemID:        "11111111-1111-4111-8111-111111111111",
					SchemaVersion: 1,
					Revision:      1,
					RevisionID:    "22222222-2222-4222-8222-222222222222",
					Envelope:      []byte("opaque-envelope"),
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	salt := []byte("0123456789abcdef")
	file := portableBackupFile{
		Magic:       portableBackupMagic,
		Version:     portableBackupLegacyVersion,
		KDF:         portableBackupKDF,
		MemoryKiB:   portableBackupMemoryKiB,
		Passes:      portableBackupPasses,
		Parallelism: portableBackupParallelism,
		Salt:        salt,
		Nonce:       bytes.Repeat([]byte{0x42}, chacha20poly1305.NonceSizeX),
	}
	key := portableBackupKey(password, salt)
	aead, err := chacha20poly1305.NewX(key)
	clearBytes(key)
	if err != nil {
		t.Fatal(err)
	}
	file.Ciphertext = aead.Seal(
		nil,
		file.Nonce,
		payload,
		portableBackupAssociatedData(file),
	)
	encoded, err := json.Marshal(file)
	if err != nil {
		t.Fatal(err)
	}
	backup, err := ReadPortableBackup(bytes.NewReader(encoded), password)
	if err != nil {
		t.Fatal(err)
	}
	if backup.AccountID != "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" ||
		len(backup.Revisions) != 1 || len(backup.Mutations) != 0 ||
		backup.Fingerprint == "" {
		t.Fatalf("compatibility vector: %+v", backup)
	}
}

func TestQueueMutationsIsAtomicAndIdempotent(t *testing.T) {
	cfg := Config{DataDir: filepath.Join(t.TempDir(), "cache")}
	if err := AuthorizeCache(
		cfg,
		"user@example.com",
		"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		[]byte("envelope"),
	); err != nil {
		t.Fatal(err)
	}
	cache, err := OpenCache(cfg, "user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	valid := EncryptedItem{
		ItemID:        "11111111-1111-4111-8111-111111111111",
		SchemaVersion: 1,
		Revision:      1,
		RevisionID:    "22222222-2222-4222-8222-222222222222",
		Envelope:      []byte("encrypted"),
	}
	invalid := valid
	invalid.ItemID = "33333333-3333-4333-8333-333333333333"
	invalid.Revision = 2
	if _, err := cache.QueueMutations([]EncryptedItem{valid, invalid}); err == nil {
		t.Fatal("invalid batch was accepted")
	}
	snapshot, err := cache.SyncSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Mutations) != 0 {
		t.Fatalf("failed batch partially queued: %+v", snapshot.Mutations)
	}
	queued, err := cache.QueueMutations([]EncryptedItem{valid})
	if err != nil || len(queued) != 1 {
		t.Fatalf("queue valid batch: %v %+v", err, queued)
	}
	queued, err = cache.QueueMutations([]EncryptedItem{valid})
	if err != nil || len(queued) != 0 {
		t.Fatalf("repeat batch was not idempotent: %v %+v", err, queued)
	}
	snapshot, err = cache.SyncSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Mutations) != 1 {
		t.Fatalf("repeat batch changed cache: %+v", snapshot.Mutations)
	}
	if _, err := cache.QueuePortableBackupMutations(nil, "empty-backup"); err != nil {
		t.Fatal(err)
	}
	data, err := cache.read()
	if err != nil || !containsRestoredBackup(data.RestoredBackups, "empty-backup") {
		t.Fatalf("empty backup marker was not recorded: %v %+v", err, data)
	}
}

func TestRestorePortableStatePreservesCursorAndRevisionGraph(t *testing.T) {
	accountID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	envelope := []byte("password-envelope")
	sourceCfg := Config{DataDir: filepath.Join(t.TempDir(), "source-cache")}
	if err := AuthorizeCache(
		sourceCfg,
		"user@example.com",
		accountID,
		envelope,
	); err != nil {
		t.Fatal(err)
	}
	source, err := OpenCache(sourceCfg, "user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	first := EncryptedItem{
		ItemID:        "11111111-1111-4111-8111-111111111111",
		SchemaVersion: 1,
		Revision:      1,
		RevisionID:    "22222222-2222-4222-8222-222222222222",
		Envelope:      []byte("first"),
	}
	second := first
	second.Revision = 2
	second.RevisionID = "33333333-3333-4333-8333-333333333333"
	second.ParentRevisionIDs = []string{first.RevisionID}
	second.Envelope = []byte("second")
	if _, err := source.QueueMutation(first, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := source.QueueMutation(second, 1); err != nil {
		t.Fatal(err)
	}
	if err := source.ApplySync("9", []string{
		first.RevisionID,
		second.RevisionID,
	}, nil); err != nil {
		t.Fatal(err)
	}
	var encoded bytes.Buffer
	if err := source.WritePortableBackup(&encoded, []byte("backup password")); err != nil {
		t.Fatal(err)
	}
	backup, err := ReadPortableBackup(
		bytes.NewReader(encoded.Bytes()),
		[]byte("backup password"),
	)
	if err != nil {
		t.Fatal(err)
	}
	destinationCfg := Config{DataDir: filepath.Join(t.TempDir(), "destination-cache")}
	if err := AuthorizeCache(
		destinationCfg,
		"user@example.com",
		accountID,
		envelope,
	); err != nil {
		t.Fatal(err)
	}
	destination, err := OpenCache(destinationCfg, "user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := destination.RestorePortableState(backup); err != nil {
		t.Fatal(err)
	}
	matched, err := destination.PortableStateMatches(backup)
	if err != nil || !matched {
		t.Fatalf("restored graph mismatch: %v", err)
	}
	if err := destination.ApplySync("10", nil, nil); err != nil {
		t.Fatal(err)
	}
	matched, err = destination.PortableStateMatches(backup)
	if err != nil || !matched {
		t.Fatalf("restored graph marker was lost after sync: %v", err)
	}
	snapshot, err := destination.SyncSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Cursor != "10" || len(snapshot.Mutations) != 0 {
		t.Fatalf("restored reconciliation state: %+v", snapshot)
	}
	heads, err := destination.ItemHeads()
	if err != nil || len(heads) != 1 || len(heads[0].Revisions) != 1 ||
		!sameEncryptedItem(heads[0].Revisions[0], second) {
		t.Fatalf("restored revision heads: %v %+v", err, heads)
	}
}

func FuzzReadPortableBackup(f *testing.F) {
	for _, seed := range []string{
		"{}",
		`{"magic":"termkeep-portable-backup","version":1}`,
		"not-json",
		"\x00\x01\x02",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, encoded []byte) {
		_, _ = ReadPortableBackup(
			bytes.NewReader(encoded),
			[]byte("backup password"),
		)
	})
}

func FuzzPreparePortableBackupImport(f *testing.F) {
	for _, seed := range []string{
		`{"type":"login","login":{"item_id":"11111111-1111-4111-8111-111111111111"}}`,
		`{"type":"folder","folder":{"item_id":"22222222-2222-4222-8222-222222222222"}}`,
		`{"type":"generic","generic":{"item_id":"33333333-3333-4333-8333-333333333333"}}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, encoded []byte) {
		var item NativeItem
		if json.Unmarshal(encoded, &item) != nil {
			return
		}
		_, _ = PreparePortableBackupImportWithNamespace(
			[]NativeItem{item},
			nil,
			"compatibility-fuzz-namespace",
		)
	})
}

func TestPreparePortableBackupImportPreservesContentAndRemapsFolders(
	t *testing.T,
) {
	totp, err := NewTOTPConfig(
		"JBSWY3DPEHPK3PXP",
		"Example",
		"user@example.com",
		"SHA256",
		8,
		60,
	)
	if err != nil {
		t.Fatal(err)
	}
	sourceFolder := FolderItem{
		ItemID: "11111111-1111-4111-8111-111111111111",
		Name:   "Imported folder",
	}
	sourceLogin := LoginItem{
		ItemID:   "22222222-2222-4222-8222-222222222222",
		Name:     "Imported login",
		Username: "user@example.com",
		Password: "same-password",
		FolderID: sourceFolder.ItemID,
		Favorite: true,
		PasswordHistory: []PasswordHistoryEntry{{
			Password:  "previous-password",
			ChangedAt: time.Date(2026, 7, 30, 0, 0, 0, 0, time.UTC),
		}},
		TOTP: &totp,
	}
	items := []NativeItem{
		{Type: NativeItemTypeFolder, Folder: &sourceFolder},
		{Type: NativeItemTypeLogin, Login: &sourceLogin},
	}
	existing := []NativeItem{{
		Type: NativeItemTypeLogin,
		Login: &LoginItem{
			ItemID:   "33333333-3333-4333-8333-333333333333",
			Name:     "Existing name",
			Username: sourceLogin.Username,
			Password: sourceLogin.Password,
			PasswordHistory: append([]PasswordHistoryEntry(nil),
				sourceLogin.PasswordHistory...),
			TOTP: &totp,
		},
	}}

	preview, err := PreparePortableBackupImport(items, existing)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Counts.Folders != 1 || preview.Counts.Logins != 1 ||
		preview.Items[0].Folder.ItemID == sourceFolder.ItemID ||
		preview.Items[1].Login.ItemID == sourceLogin.ItemID ||
		preview.Items[1].Login.FolderID != preview.Items[0].Folder.ItemID ||
		preview.Items[1].Login.PasswordHistory[0].Password !=
			sourceLogin.PasswordHistory[0].Password ||
		preview.Items[1].Login.TOTP == nil ||
		preview.Items[1].Login.TOTP.Digits != 8 {
		t.Fatalf("prepared restore: %+v", preview.Items)
	}
	if preview.Items[1].Login.Name != "Imported login (Duplicada)" {
		t.Fatalf("duplicate naming: %+v", preview.Items[1].Login.Name)
	}
}

func TestPreparePortableBackupImportNamespaceRetrySkipsDuplicateName(t *testing.T) {
	source := NativeItem{
		Type: NativeItemTypeLogin,
		Login: &LoginItem{
			ItemID:   "11111111-1111-4111-8111-111111111111",
			Name:     "Imported login",
			Username: "user@example.com",
			Password: "same-password",
		},
	}
	existing := NativeItem{
		Type: NativeItemTypeLogin,
		Login: &LoginItem{
			ItemID:   "22222222-2222-4222-8222-222222222222",
			Name:     "Existing login",
			Username: "user@example.com",
			Password: "same-password",
		},
	}
	first, err := PreparePortableBackupImportWithNamespace(
		[]NativeItem{source},
		[]NativeItem{existing},
		"backup-fingerprint",
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Items) != 1 || first.Items[0].Login.Name !=
		"Imported login (Duplicada)" {
		t.Fatalf("first restore preview: %+v", first)
	}
	second, err := PreparePortableBackupImportWithNamespace(
		[]NativeItem{source},
		[]NativeItem{existing, first.Items[0]},
		"backup-fingerprint",
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Items) != 0 || len(second.Errors) != 0 {
		t.Fatalf("retry was not idempotent: %+v", second)
	}
}
