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
const secureNoteItemSchemaVersion = 1
const folderItemSchemaVersion = 1
const itemEnvelopeVersion = 1
const itemPlaintextVersion = 1
const maxPasswordHistoryEntries = 5

var ErrInvalidItemEnvelope = errors.New("invalid item envelope")

type CustomField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type PasswordHistoryEntry struct {
	Password  string    `json:"password"`
	ChangedAt time.Time `json:"changed_at"`
}

type LoginItem struct {
	ItemID          string                 `json:"item_id"`
	Name            string                 `json:"name"`
	Username        string                 `json:"username"`
	Password        string                 `json:"password"`
	PasswordHistory []PasswordHistoryEntry `json:"password_history,omitempty"`
	FolderID        string                 `json:"folder_id,omitempty"`
	Favorite        bool                   `json:"favorite,omitempty"`
	URLs            []string               `json:"urls"`
	Notes           string                 `json:"notes"`
	CustomFields    []CustomField          `json:"custom_fields"`
	TOTP            *TOTPConfig            `json:"totp,omitempty"`
}

type SecureNoteItem struct {
	ItemID   string `json:"item_id"`
	Title    string `json:"title"`
	Content  string `json:"content"`
	FolderID string `json:"folder_id,omitempty"`
	Favorite bool   `json:"favorite,omitempty"`
}

type FolderItem struct {
	ItemID string `json:"item_id"`
	Name   string `json:"name"`
}

type NativeItemType string

const (
	NativeItemTypeLogin      NativeItemType = "login"
	NativeItemTypeSecureNote NativeItemType = "secure_note"
	NativeItemTypeFolder     NativeItemType = "folder"
)

type NativeItem struct {
	Type       NativeItemType  `json:"type"`
	Login      *LoginItem      `json:"login,omitempty"`
	SecureNote *SecureNoteItem `json:"secure_note,omitempty"`
	Folder     *FolderItem     `json:"folder,omitempty"`
}

type EncryptedItem struct {
	ItemID            string   `json:"item_id"`
	SchemaVersion     int      `json:"schema_version"`
	Revision          uint64   `json:"revision"`
	RevisionID        string   `json:"revision_id"`
	ParentRevisionIDs []string `json:"parent_revision_ids"`
	Deleted           bool     `json:"deleted"`
	Purged            bool     `json:"purged"`
	Envelope          []byte   `json:"envelope"`
}

type itemEnvelope struct {
	Version    int    `json:"version"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

type loginPlaintext struct {
	Type    string `json:"type"`
	Version int    `json:"version"`
	LoginItem
}

type secureNotePlaintext struct {
	Type    string `json:"type"`
	Version int    `json:"version"`
	SecureNoteItem
}

type folderPlaintext struct {
	Type    string `json:"type"`
	Version int    `json:"version"`
	FolderItem
}

func RotateLoginPassword(
	login LoginItem,
	password string,
	changedAt time.Time,
) LoginItem {
	history := append(
		[]PasswordHistoryEntry(nil),
		login.PasswordHistory...,
	)
	if password == login.Password {
		login.PasswordHistory = history
		return login
	}
	if login.Password != "" {
		history = append([]PasswordHistoryEntry{{
			Password:  login.Password,
			ChangedAt: changedAt.UTC(),
		}}, history...)
		if len(history) > maxPasswordHistoryEntries {
			history = history[:maxPasswordHistoryEntries]
		}
	}
	login.Password = password
	login.PasswordHistory = history
	return login
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
	if login.TOTP != nil {
		if err := ValidateTOTPConfig(*login.TOTP); err != nil {
			return EncryptedItem{}, err
		}
	}
	return encryptItem(
		vaultKey,
		accountID,
		login.ItemID,
		loginItemSchemaVersion,
		revision,
		loginPlaintext{
			Type:      "login",
			Version:   itemPlaintextVersion,
			LoginItem: login,
		},
	)
}

func EncryptSecureNote(
	vaultKey []byte,
	accountID string,
	note SecureNoteItem,
	revision uint64,
) (EncryptedItem, error) {
	if len(vaultKey) != chacha20poly1305.KeySize ||
		accountID == "" || note.ItemID == "" || revision == 0 {
		return EncryptedItem{}, ErrInvalidItemEnvelope
	}
	return encryptItem(
		vaultKey,
		accountID,
		note.ItemID,
		secureNoteItemSchemaVersion,
		revision,
		secureNotePlaintext{
			Type:           "secure_note",
			Version:        itemPlaintextVersion,
			SecureNoteItem: note,
		},
	)
}

func EncryptFolder(
	vaultKey []byte,
	accountID string,
	folder FolderItem,
	revision uint64,
) (EncryptedItem, error) {
	if len(vaultKey) != chacha20poly1305.KeySize ||
		accountID == "" || folder.ItemID == "" || revision == 0 {
		return EncryptedItem{}, ErrInvalidItemEnvelope
	}
	return encryptItem(
		vaultKey,
		accountID,
		folder.ItemID,
		folderItemSchemaVersion,
		revision,
		folderPlaintext{
			Type:       "folder",
			Version:    itemPlaintextVersion,
			FolderItem: folder,
		},
	)
}

func encryptItem(
	vaultKey []byte,
	accountID string,
	itemID string,
	schemaVersion int,
	revision uint64,
	value any,
) (EncryptedItem, error) {
	plaintext, err := json.Marshal(value)
	if err != nil {
		return EncryptedItem{}, fmt.Errorf("encode item: %w", err)
	}
	defer clearBytes(plaintext)

	key := derivePurposeKey(vaultKey, "item/"+itemID)
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
			accountID, itemID, schemaVersion, revision),
	)
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return EncryptedItem{}, fmt.Errorf("encode item envelope: %w", err)
	}
	return EncryptedItem{
		ItemID:        itemID,
		SchemaVersion: schemaVersion,
		Revision:      revision,
		Envelope:      encoded,
	}, nil
}

func DecryptLogin(
	vaultKey []byte,
	accountID string,
	item EncryptedItem,
) (LoginItem, error) {
	opened, err := DecryptNativeItem(vaultKey, accountID, item)
	if err != nil {
		return LoginItem{}, err
	}
	if opened.Type != NativeItemTypeLogin || opened.Login == nil {
		return LoginItem{}, ErrInvalidItemEnvelope
	}
	return *opened.Login, nil
}

func DecryptSecureNote(
	vaultKey []byte,
	accountID string,
	item EncryptedItem,
) (SecureNoteItem, error) {
	opened, err := DecryptNativeItem(vaultKey, accountID, item)
	if err != nil {
		return SecureNoteItem{}, err
	}
	if opened.Type != NativeItemTypeSecureNote ||
		opened.SecureNote == nil {
		return SecureNoteItem{}, ErrInvalidItemEnvelope
	}
	return *opened.SecureNote, nil
}

func DecryptFolder(
	vaultKey []byte,
	accountID string,
	item EncryptedItem,
) (FolderItem, error) {
	opened, err := DecryptNativeItem(vaultKey, accountID, item)
	if err != nil {
		return FolderItem{}, err
	}
	if opened.Type != NativeItemTypeFolder || opened.Folder == nil {
		return FolderItem{}, ErrInvalidItemEnvelope
	}
	return *opened.Folder, nil
}

func DecryptNativeItem(
	vaultKey []byte,
	accountID string,
	item EncryptedItem,
) (NativeItem, error) {
	if len(vaultKey) != chacha20poly1305.KeySize ||
		accountID == "" || item.ItemID == "" ||
		item.SchemaVersion < 1 || item.Revision == 0 {
		return NativeItem{}, ErrInvalidItemEnvelope
	}
	plaintext, err := decryptItem(vaultKey, accountID, item)
	if err != nil {
		return NativeItem{}, err
	}
	defer clearBytes(plaintext)
	var header struct {
		Type    NativeItemType `json:"type"`
		Version int            `json:"version"`
	}
	if err := json.Unmarshal(plaintext, &header); err != nil {
		return NativeItem{}, ErrInvalidItemEnvelope
	}
	switch header.Type {
	case NativeItemTypeLogin:
		var decoded loginPlaintext
		if item.SchemaVersion != loginItemSchemaVersion ||
			json.Unmarshal(plaintext, &decoded) != nil ||
			(decoded.Version != 0 &&
				decoded.Version != itemPlaintextVersion) ||
			decoded.ItemID != item.ItemID {
			return NativeItem{}, ErrInvalidItemEnvelope
		}
		return NativeItem{
			Type:  NativeItemTypeLogin,
			Login: &decoded.LoginItem,
		}, nil
	case NativeItemTypeSecureNote:
		var decoded secureNotePlaintext
		if item.SchemaVersion != secureNoteItemSchemaVersion ||
			json.Unmarshal(plaintext, &decoded) != nil ||
			decoded.Version != itemPlaintextVersion ||
			decoded.ItemID != item.ItemID {
			return NativeItem{}, ErrInvalidItemEnvelope
		}
		return NativeItem{
			Type:       NativeItemTypeSecureNote,
			SecureNote: &decoded.SecureNoteItem,
		}, nil
	case NativeItemTypeFolder:
		var decoded folderPlaintext
		if item.SchemaVersion != folderItemSchemaVersion ||
			json.Unmarshal(plaintext, &decoded) != nil ||
			decoded.Version != itemPlaintextVersion ||
			decoded.ItemID != item.ItemID {
			return NativeItem{}, ErrInvalidItemEnvelope
		}
		return NativeItem{
			Type:   NativeItemTypeFolder,
			Folder: &decoded.FolderItem,
		}, nil
	default:
		return NativeItem{}, ErrInvalidItemEnvelope
	}
}

func decryptItem(
	vaultKey []byte,
	accountID string,
	item EncryptedItem,
) ([]byte, error) {
	var envelope itemEnvelope
	if err := json.Unmarshal(item.Envelope, &envelope); err != nil ||
		envelope.Version != itemEnvelopeVersion {
		return nil, ErrInvalidItemEnvelope
	}
	key := derivePurposeKey(vaultKey, "item/"+item.ItemID)
	defer clearBytes(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil || len(envelope.Nonce) != aead.NonceSize() {
		return nil, ErrInvalidItemEnvelope
	}
	plaintext, err := aead.Open(
		nil,
		envelope.Nonce,
		envelope.Ciphertext,
		itemAssociatedData(
			accountID, item.ItemID, item.SchemaVersion, item.Revision),
	)
	if err != nil {
		return nil, ErrInvalidItemEnvelope
	}
	return plaintext, nil
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
