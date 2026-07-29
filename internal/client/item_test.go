package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

func TestLoginPasswordRotationKeepsFiveMostRecentWithTimestamps(t *testing.T) {
	login := LoginItem{
		ItemID:   "11111111-1111-4111-8111-111111111111",
		Name:     "Production database",
		Password: "Password-0",
	}
	start := time.Date(2026, time.July, 28, 12, 0, 0, 0, time.UTC)

	for rotation := 1; rotation <= 7; rotation++ {
		login = RotateLoginPassword(
			login,
			fmt.Sprintf("Password-%d", rotation),
			start.Add(time.Duration(rotation)*time.Hour),
		)
	}

	if login.Password != "Password-7" {
		t.Fatalf("current password: got %q", login.Password)
	}
	want := []PasswordHistoryEntry{
		{Password: "Password-6", ChangedAt: start.Add(7 * time.Hour)},
		{Password: "Password-5", ChangedAt: start.Add(6 * time.Hour)},
		{Password: "Password-4", ChangedAt: start.Add(5 * time.Hour)},
		{Password: "Password-3", ChangedAt: start.Add(4 * time.Hour)},
		{Password: "Password-2", ChangedAt: start.Add(3 * time.Hour)},
	}
	if !reflect.DeepEqual(login.PasswordHistory, want) {
		t.Fatalf(
			"password history:\nwant: %+v\ngot:  %+v",
			want,
			login.PasswordHistory,
		)
	}
}

func TestEncryptedLoginRoundTripHidesSemanticFields(t *testing.T) {
	vaultKey := bytes.Repeat([]byte{0x42}, 32)
	login := LoginItem{
		ItemID:   "11111111-1111-4111-8111-111111111111",
		Name:     "Production database",
		Username: "operator@example.com",
		Password: "Database-Password-Sentinel",
		PasswordHistory: []PasswordHistoryEntry{
			{
				Password: "Previous-Database-Password-Sentinel",
				ChangedAt: time.Date(
					2026, time.July, 28, 13, 45, 0, 0, time.UTC),
			},
		},
		FolderID: "22222222-2222-4222-8222-222222222222",
		Favorite: true,
		URLs:     []string{"https://db.example.com", "postgres://db.internal"},
		Notes:    "Primary credentials",
		CustomFields: []CustomField{
			{Name: "region", Value: "us-east-1"},
			{Name: "owner", Value: "platform"},
		},
		TOTP: &TOTPConfig{
			Secret:    "JBSWY3DPEHPK3PXP",
			Issuer:    "Example Co",
			Account:   "operator@example.com",
			Algorithm: TOTPAlgorithmSHA256,
			Digits:    8,
			Period:    45,
		},
	}

	encrypted, err := EncryptLogin(
		vaultKey,
		"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		login,
		1,
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, plaintext := range []string{
		login.Name,
		login.Username,
		login.Password,
		login.PasswordHistory[0].Password,
		login.PasswordHistory[0].ChangedAt.Format(time.RFC3339),
		login.URLs[0],
		login.Notes,
		login.CustomFields[0].Value,
		login.TOTP.Secret,
		login.TOTP.Issuer,
		login.TOTP.Account,
	} {
		if bytes.Contains(encrypted.Envelope, []byte(plaintext)) {
			t.Fatalf("encrypted envelope contains %q", plaintext)
		}
	}

	decrypted, err := DecryptLogin(
		vaultKey,
		"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		encrypted,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decrypted, login) {
		t.Fatalf("round trip differs:\nwant: %+v\ngot:  %+v", login, decrypted)
	}
}

func TestEncryptedSecureNoteRoundTripHidesSemanticFields(t *testing.T) {
	vaultKey := bytes.Repeat([]byte{0x42}, 32)
	note := SecureNoteItem{
		ItemID: "11111111-1111-4111-8111-111111111111",
		Title:  "Production recovery procedure",
		Content: "Sensitive-Note-Content-Sentinel\n" +
			"Second confidential line",
		FolderID: "22222222-2222-4222-8222-222222222222",
		Favorite: true,
	}

	encrypted, err := EncryptSecureNote(
		vaultKey,
		"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		note,
		1,
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, plaintext := range []string{note.Title, note.Content} {
		if bytes.Contains(encrypted.Envelope, []byte(plaintext)) {
			t.Fatalf("encrypted envelope contains %q", plaintext)
		}
	}

	decrypted, err := DecryptSecureNote(
		vaultKey,
		"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		encrypted,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decrypted, note) {
		t.Fatalf("round trip differs:\nwant: %+v\ngot:  %+v", note, decrypted)
	}
}

func TestEncryptedFolderRoundTripHidesName(t *testing.T) {
	vaultKey := bytes.Repeat([]byte{0x42}, 32)
	folder := FolderItem{
		ItemID: "11111111-1111-4111-8111-111111111111",
		Name:   "Production infrastructure",
	}

	encrypted, err := EncryptFolder(
		vaultKey,
		"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		folder,
		1,
	)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted.Envelope, []byte(folder.Name)) {
		t.Fatalf("encrypted envelope contains Folder name %q", folder.Name)
	}

	decrypted, err := DecryptFolder(
		vaultKey,
		"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		encrypted,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decrypted, folder) {
		t.Fatalf("round trip differs:\nwant: %+v\ngot:  %+v", folder, decrypted)
	}
}

func TestEncryptedGenericItemRoundTripHidesImportedFields(t *testing.T) {
	vaultKey := bytes.Repeat([]byte{0x42}, 32)
	generic := GenericItem{
		ItemID:     "11111111-1111-4111-8111-111111111111",
		Title:      "Corporate card",
		Source:     "bitwarden",
		SourceType: "card",
		FolderID:   "22222222-2222-4222-8222-222222222222",
		Favorite:   true,
		Data: json.RawMessage(`{
			"type": 3,
			"name": "Corporate card",
			"card": {
				"number": "4111111111111111",
				"code": "Security-Code-Sentinel"
			}
		}`),
	}

	encrypted, err := EncryptGenericItem(
		vaultKey,
		"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		generic,
		1,
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, plaintext := range []string{
		generic.Title,
		generic.Source,
		generic.SourceType,
		"4111111111111111",
		"Security-Code-Sentinel",
	} {
		if bytes.Contains(encrypted.Envelope, []byte(plaintext)) {
			t.Fatalf("encrypted envelope contains %q", plaintext)
		}
	}

	decrypted, err := DecryptGenericItem(
		vaultKey,
		"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		encrypted,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decrypted, generic) {
		t.Fatalf("round trip differs:\nwant: %+v\ngot:  %+v",
			generic, decrypted)
	}
	opened, err := DecryptNativeItem(
		vaultKey,
		"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		encrypted,
	)
	if err != nil ||
		opened.Type != NativeItemTypeGeneric ||
		!reflect.DeepEqual(opened.Generic, &generic) {
		t.Fatalf("native Generic Item: %+v, %v", opened, err)
	}
}

func TestEncryptedItemTypeCannotBeOpenedAsAnotherNativeType(t *testing.T) {
	vaultKey := bytes.Repeat([]byte{0x42}, 32)
	accountID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	itemID := "11111111-1111-4111-8111-111111111111"
	login, err := EncryptLogin(vaultKey, accountID, LoginItem{
		ItemID: itemID,
		Name:   "Login",
	}, 1)
	if err != nil {
		t.Fatal(err)
	}
	note, err := EncryptSecureNote(vaultKey, accountID, SecureNoteItem{
		ItemID: itemID,
		Title:  "Secure Note",
	}, 1)
	if err != nil {
		t.Fatal(err)
	}

	if opened, err := DecryptSecureNote(
		vaultKey, accountID, login,
	); err == nil || !reflect.DeepEqual(opened, SecureNoteItem{}) {
		t.Fatalf("Login opened as Secure Note: %+v, %v", opened, err)
	}
	if opened, err := DecryptLogin(
		vaultKey, accountID, note,
	); err == nil || !reflect.DeepEqual(opened, LoginItem{}) {
		t.Fatalf("Secure Note opened as Login: %+v, %v", opened, err)
	}
}

func TestDecryptNativeItemReportsEncryptedType(t *testing.T) {
	vaultKey := bytes.Repeat([]byte{0x42}, 32)
	accountID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	note := SecureNoteItem{
		ItemID:  "11111111-1111-4111-8111-111111111111",
		Title:   "Recovery procedure",
		Content: "Sensitive content",
	}
	encrypted, err := EncryptSecureNote(
		vaultKey, accountID, note, 1)
	if err != nil {
		t.Fatal(err)
	}

	opened, err := DecryptNativeItem(vaultKey, accountID, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if opened.Type != NativeItemTypeSecureNote ||
		opened.SecureNote == nil ||
		opened.Login != nil ||
		!reflect.DeepEqual(*opened.SecureNote, note) {
		t.Fatalf("native Item type/content: %+v", opened)
	}
}

func TestDecryptNativeItemReportsEncryptedFolderType(t *testing.T) {
	vaultKey := bytes.Repeat([]byte{0x42}, 32)
	accountID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	folder := FolderItem{
		ItemID: "11111111-1111-4111-8111-111111111111",
		Name:   "Infrastructure",
	}
	encrypted, err := EncryptFolder(
		vaultKey, accountID, folder, 1)
	if err != nil {
		t.Fatal(err)
	}

	opened, err := DecryptNativeItem(vaultKey, accountID, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if opened.Type != NativeItemTypeFolder ||
		opened.Folder == nil ||
		opened.Login != nil ||
		opened.SecureNote != nil ||
		!reflect.DeepEqual(*opened.Folder, folder) {
		t.Fatalf("native Folder type/content: %+v", opened)
	}
}

func TestEncryptedLoginUsesRandomNonce(t *testing.T) {
	vaultKey := bytes.Repeat([]byte{0x42}, 32)
	login := LoginItem{
		ItemID:   "11111111-1111-4111-8111-111111111111",
		Name:     "Production database",
		Password: "Password-Sentinel",
	}
	first, err := EncryptLogin(
		vaultKey, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", login, 1)
	if err != nil {
		t.Fatal(err)
	}
	second, err := EncryptLogin(
		vaultKey, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", login, 1)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first.Envelope, second.Envelope) {
		t.Fatal("encrypting the same Login reused its nonce")
	}
}

func TestEncryptedLoginRejectsCiphertextAndAssociatedDataTampering(t *testing.T) {
	vaultKey := bytes.Repeat([]byte{0x42}, 32)
	accountID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	encrypted, err := EncryptLogin(vaultKey, accountID, LoginItem{
		ItemID:   "11111111-1111-4111-8111-111111111111",
		Name:     "Sensitive login",
		Password: "Password-Sentinel",
	}, 1)
	if err != nil {
		t.Fatal(err)
	}
	var envelope itemEnvelope
	if err := json.Unmarshal(encrypted.Envelope, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Ciphertext[0] ^= 1
	tamperedCiphertext, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		accountID string
		item      EncryptedItem
	}{
		{
			name:      "ciphertext",
			accountID: accountID,
			item: EncryptedItem{
				ItemID:        encrypted.ItemID,
				SchemaVersion: encrypted.SchemaVersion,
				Revision:      encrypted.Revision,
				Envelope:      tamperedCiphertext,
			},
		},
		{
			name:      "account",
			accountID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
			item:      encrypted,
		},
		{
			name:      "item",
			accountID: accountID,
			item: EncryptedItem{
				ItemID:        "22222222-2222-4222-8222-222222222222",
				SchemaVersion: encrypted.SchemaVersion,
				Revision:      encrypted.Revision,
				Envelope:      encrypted.Envelope,
			},
		},
		{
			name:      "schema",
			accountID: accountID,
			item: EncryptedItem{
				ItemID:        encrypted.ItemID,
				SchemaVersion: encrypted.SchemaVersion + 1,
				Revision:      encrypted.Revision,
				Envelope:      encrypted.Envelope,
			},
		},
		{
			name:      "revision",
			accountID: accountID,
			item: EncryptedItem{
				ItemID:        encrypted.ItemID,
				SchemaVersion: encrypted.SchemaVersion,
				Revision:      encrypted.Revision + 1,
				Envelope:      encrypted.Envelope,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			login, err := DecryptLogin(vaultKey, test.accountID, test.item)
			if err == nil {
				t.Fatalf("tampered item decrypted: %+v", login)
			}
			if !reflect.DeepEqual(login, LoginItem{}) {
				t.Fatalf("tampered item returned partial plaintext: %+v", login)
			}
		})
	}
}

func TestClientStoresAndListsEncryptedItems(t *testing.T) {
	want := EncryptedItem{
		ItemID:        "11111111-1111-4111-8111-111111111111",
		SchemaVersion: 1,
		Revision:      1,
		Envelope:      []byte{0xde, 0xad, 0xbe, 0xef},
	}
	var stored EncryptedItem
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer access-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodPut &&
			r.URL.Path == "/api/v1/items/"+want.ItemID:
			var body struct {
				SchemaVersion int    `json:"schema_version"`
				Revision      uint64 `json:"revision"`
				Envelope      []byte `json:"envelope"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			stored = EncryptedItem{
				ItemID:        want.ItemID,
				SchemaVersion: body.SchemaVersion,
				Revision:      body.Revision,
				Envelope:      body.Envelope,
			}
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/items":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"items": []EncryptedItem{stored},
			})
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer server.Close()

	cfg := Config{ServerURL: server.URL}
	if err := PutItem(context.Background(), cfg, "access-token", want); err != nil {
		t.Fatal(err)
	}
	got, err := ListItems(context.Background(), cfg, "access-token")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !reflect.DeepEqual(got[0], want) {
		t.Fatalf("encrypted item transport changed: %+v", got)
	}
}

func TestEncryptedLoginTransportContainsNoPlaintext(t *testing.T) {
	login := LoginItem{
		ItemID:   "11111111-1111-4111-8111-111111111111",
		Name:     "Production database sentinel",
		Username: "operator-sentinel@example.com",
		Password: "Password-Sentinel",
		URLs:     []string{"https://sentinel.example.com"},
		Notes:    "Notes sentinel",
		CustomFields: []CustomField{
			{Name: "region-sentinel", Value: "value-sentinel"},
		},
		TOTP: &TOTPConfig{
			Secret:    "JBSWY3DPEHPK3PXP",
			Issuer:    "TOTP-Issuer-Sentinel",
			Account:   "totp-account-sentinel@example.com",
			Algorithm: TOTPAlgorithmSHA512,
			Digits:    8,
			Period:    60,
		},
	}
	item, err := EncryptLogin(
		bytes.Repeat([]byte{0x42}, 32),
		"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		login,
		1,
	)
	if err != nil {
		t.Fatal(err)
	}

	var requestBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	if err := PutItem(
		context.Background(),
		Config{ServerURL: server.URL},
		"access-token",
		item,
	); err != nil {
		t.Fatal(err)
	}
	for _, plaintext := range []string{
		login.Name,
		login.Username,
		login.Password,
		login.URLs[0],
		login.Notes,
		login.CustomFields[0].Name,
		login.CustomFields[0].Value,
		login.TOTP.Secret,
		login.TOTP.Issuer,
		login.TOTP.Account,
	} {
		if bytes.Contains(requestBody, []byte(plaintext)) {
			t.Fatalf("item request contains %q", plaintext)
		}
	}
}
