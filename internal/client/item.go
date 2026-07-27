package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const loginItemSchemaVersion = 1
const itemEnvelopeVersion = 1

var ErrInvalidItemEnvelope = errors.New("invalid item envelope")

type CustomField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type LoginItem struct {
	ItemID       string        `json:"item_id"`
	Name         string        `json:"name"`
	Username     string        `json:"username"`
	Password     string        `json:"password"`
	URLs         []string      `json:"urls"`
	Notes        string        `json:"notes"`
	CustomFields []CustomField `json:"custom_fields"`
}

type EncryptedItem struct {
	ItemID        string `json:"item_id"`
	SchemaVersion int    `json:"schema_version"`
	Revision      uint64 `json:"revision"`
	Envelope      []byte `json:"envelope"`
}

type itemEnvelope struct {
	Version    int    `json:"version"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

type loginPlaintext struct {
	Type string `json:"type"`
	LoginItem
}

func NewItemID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate item ID: %w", err)
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}

func EncryptLogin(
	vaultKey []byte,
	accountID string,
	login LoginItem,
	revision uint64,
) (EncryptedItem, error) {
	if len(vaultKey) != chacha20poly1305.KeySize ||
		accountID == "" || login.ItemID == "" || revision == 0 {
		return EncryptedItem{}, ErrInvalidItemEnvelope
	}
	plaintext, err := json.Marshal(loginPlaintext{
		Type:      "login",
		LoginItem: login,
	})
	if err != nil {
		return EncryptedItem{}, fmt.Errorf("encode login: %w", err)
	}
	defer clearBytes(plaintext)

	key := derivePurposeKey(vaultKey, "item/"+login.ItemID)
	defer clearBytes(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return EncryptedItem{}, ErrInvalidItemEnvelope
	}
	envelope := itemEnvelope{
		Version: itemEnvelopeVersion,
		Nonce:   make([]byte, aead.NonceSize()),
	}
	if _, err := rand.Read(envelope.Nonce); err != nil {
		return EncryptedItem{}, fmt.Errorf("generate item nonce: %w", err)
	}
	envelope.Ciphertext = aead.Seal(
		nil,
		envelope.Nonce,
		plaintext,
		itemAssociatedData(
			accountID, login.ItemID, loginItemSchemaVersion, revision),
	)
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return EncryptedItem{}, fmt.Errorf("encode item envelope: %w", err)
	}
	return EncryptedItem{
		ItemID:        login.ItemID,
		SchemaVersion: loginItemSchemaVersion,
		Revision:      revision,
		Envelope:      encoded,
	}, nil
}

func DecryptLogin(
	vaultKey []byte,
	accountID string,
	item EncryptedItem,
) (LoginItem, error) {
	if len(vaultKey) != chacha20poly1305.KeySize ||
		accountID == "" || item.ItemID == "" ||
		item.SchemaVersion != loginItemSchemaVersion || item.Revision == 0 {
		return LoginItem{}, ErrInvalidItemEnvelope
	}
	var envelope itemEnvelope
	if err := json.Unmarshal(item.Envelope, &envelope); err != nil ||
		envelope.Version != itemEnvelopeVersion {
		return LoginItem{}, ErrInvalidItemEnvelope
	}
	key := derivePurposeKey(vaultKey, "item/"+item.ItemID)
	defer clearBytes(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil || len(envelope.Nonce) != aead.NonceSize() {
		return LoginItem{}, ErrInvalidItemEnvelope
	}
	plaintext, err := aead.Open(
		nil,
		envelope.Nonce,
		envelope.Ciphertext,
		itemAssociatedData(
			accountID, item.ItemID, item.SchemaVersion, item.Revision),
	)
	if err != nil {
		return LoginItem{}, ErrInvalidItemEnvelope
	}
	defer clearBytes(plaintext)
	var decoded loginPlaintext
	if err := json.Unmarshal(plaintext, &decoded); err != nil ||
		decoded.Type != "login" || decoded.ItemID != item.ItemID {
		return LoginItem{}, ErrInvalidItemEnvelope
	}
	return decoded.LoginItem, nil
}

func itemAssociatedData(
	accountID string,
	itemID string,
	schemaVersion int,
	revision uint64,
) []byte {
	return []byte(fmt.Sprintf(
		"termkeep/item-envelope/v1/account/%s/item/%s/schema/%d/revision/%d",
		accountID,
		itemID,
		schemaVersion,
		revision,
	))
}

func PutItem(
	ctx context.Context,
	cfg Config,
	accessToken string,
	item EncryptedItem,
) error {
	if accessToken == "" {
		return errors.New("access token is required")
	}
	if item.ItemID == "" || item.SchemaVersion < 1 ||
		item.Revision < 1 || len(item.Envelope) == 0 {
		return ErrInvalidItemEnvelope
	}
	if err := validateServerURL(cfg.ServerURL); err != nil {
		return err
	}
	httpClient, err := newHTTPClient(cfg)
	if err != nil {
		return err
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	body, err := json.Marshal(map[string]any{
		"schema_version": item.SchemaVersion,
		"revision":       item.Revision,
		"envelope":       item.Envelope,
	})
	if err != nil {
		return fmt.Errorf("encode item: %w", err)
	}
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPut,
		cfg.ServerURL+"/api/v1/items/"+url.PathEscape(item.ItemID),
		bytes.NewReader(body),
	)
	if err != nil {
		return fmt.Errorf("build put item request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+accessToken)
	request.Header.Set("Content-Type", "application/json")
	response, err := httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("put item: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("put item: server returned HTTP %d", response.StatusCode)
	}
	return nil
}

func ListItems(
	ctx context.Context,
	cfg Config,
	accessToken string,
) ([]EncryptedItem, error) {
	if accessToken == "" {
		return nil, errors.New("access token is required")
	}
	if err := validateServerURL(cfg.ServerURL); err != nil {
		return nil, err
	}
	httpClient, err := newHTTPClient(cfg)
	if err != nil {
		return nil, err
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(
		ctx, http.MethodGet, cfg.ServerURL+"/api/v1/items", nil)
	if err != nil {
		return nil, fmt.Errorf("build list items request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+accessToken)
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("list items: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list items: server returned HTTP %d", response.StatusCode)
	}
	var body struct {
		Items []EncryptedItem `json:"items"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode items: %w", err)
	}
	return body.Items, nil
}
