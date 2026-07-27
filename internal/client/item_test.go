package client

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestEncryptedLoginRoundTripHidesSemanticFields(t *testing.T) {
	vaultKey := bytes.Repeat([]byte{0x42}, 32)
	login := LoginItem{
		ItemID:   "11111111-1111-4111-8111-111111111111",
		Name:     "Production database",
		Username: "operator@example.com",
		Password: "Database-Password-Sentinel",
		URLs:     []string{"https://db.example.com", "postgres://db.internal"},
		Notes:    "Primary credentials",
		CustomFields: []CustomField{
			{Name: "region", Value: "us-east-1"},
			{Name: "owner", Value: "platform"},
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
		login.URLs[0],
		login.Notes,
		login.CustomFields[0].Value,
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
	} {
		if bytes.Contains(requestBody, []byte(plaintext)) {
			t.Fatalf("item request contains %q", plaintext)
		}
	}
}
