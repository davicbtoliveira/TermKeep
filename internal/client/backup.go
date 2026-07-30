package client

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	portableBackupLegacyVersion = 1
	portableBackupFormatVersion = 2
	portableBackupMagic         = "termkeep-portable-backup"
	portableBackupKDF           = "argon2id"
	portableBackupMemoryKiB     = 64 * 1024
	portableBackupPasses        = 3
	portableBackupParallelism   = 4
	portableBackupSaltSize      = 16
	portableBackupMaxFileSize   = 64 << 20
)

var ErrInvalidPortableBackup = errors.New("invalid portable backup")

// PortableBackup is the decrypted payload of a portable backup. Its Revisions
// retain Item envelopes encrypted with the Vault key, while Items carries the
// semantic values needed for cross-Vault restore.
type PortableBackup struct {
	AccountID             string
	Email                 string
	PasswordVaultEnvelope []byte
	Revisions             map[string]map[string]EncryptedItem
	Mutations             []Mutation
	Cursor                string
	FormatVersion         int
	// Items contains decrypted item values protected by the backup password.
	// It makes a backup portable to a Vault with a different Vault key. Older
	// backups may leave this field nil and can only be restored to the source
	// Vault account.
	Items []NativeItem
	// Fingerprint is stable for the exact authenticated backup file and is used
	// as the namespace for idempotent semantic imports.
	Fingerprint string
}

type portableBackupPayload struct {
	Version   int                                 `json:"version"`
	AccountID string                              `json:"account_id"`
	Email     string                              `json:"email"`
	Envelope  []byte                              `json:"password_vault_envelope"`
	Revisions map[string]map[string]EncryptedItem `json:"revisions"`
	Mutations []Mutation                          `json:"mutations"`
	Cursor    string                              `json:"cursor"`
	Items     []NativeItem                        `json:"items,omitempty"`
}

type portableBackupFile struct {
	Magic       string `json:"magic"`
	Version     int    `json:"version"`
	KDF         string `json:"kdf"`
	MemoryKiB   uint32 `json:"memory_kib"`
	Passes      uint32 `json:"passes"`
	Parallelism uint8  `json:"parallelism"`
	Salt        []byte `json:"salt"`
	Nonce       []byte `json:"nonce"`
	Ciphertext  []byte `json:"ciphertext"`
}

// WritePortableBackup encrypts the complete local cache to writer using the
// v1 opaque format. Use WritePortableBackupWithItems for cross-Vault restore.
func (c *Cache) WritePortableBackup(
	writer io.Writer,
	backupPassword []byte,
) error {
	return c.writePortableBackup(writer, backupPassword, nil)
}

// WritePortableBackupWithItems writes a complete backup and includes the
// decrypted item values inside the backup ciphertext. This permits restore to
// a different Vault key while retaining the encrypted cache graph for
// same-account restores.
func (c *Cache) WritePortableBackupWithItems(
	writer io.Writer,
	backupPassword []byte,
	items []NativeItem,
) error {
	if items == nil {
		items = []NativeItem{}
	}
	return c.writePortableBackup(writer, backupPassword, items)
}

func (c *Cache) writePortableBackup(
	writer io.Writer,
	backupPassword []byte,
	items []NativeItem,
) error {
	if writer == nil {
		return errors.New("backup writer is required")
	}
	if len(backupPassword) == 0 {
		return errors.New("backup password is required")
	}
	if c == nil {
		return errors.New("encrypted cache is required")
	}
	data, err := c.read()
	if err != nil {
		return err
	}
	return writePortableBackup(writer, data, backupPassword, items)
}

// WritePortableBackupFile writes a mode-0600 portable backup atomically.
func (c *Cache) WritePortableBackupFile(
	path string,
	backupPassword []byte,
) error {
	return c.writePortableBackupFile(path, backupPassword, nil)
}

// WritePortableBackupFileWithItems writes a portable backup atomically and
// includes decrypted item values in its authenticated ciphertext.
func (c *Cache) WritePortableBackupFileWithItems(
	path string,
	backupPassword []byte,
	items []NativeItem,
) error {
	if items == nil {
		items = []NativeItem{}
	}
	return c.writePortableBackupFile(path, backupPassword, items)
}

// PortableBackupSnapshot captures the encrypted cache graph at one point in
// time. Callers can decrypt its heads separately and then write the snapshot
// without mixing them with a later cache revision.
func (c *Cache) PortableBackupSnapshot() (PortableBackup, error) {
	if c == nil {
		return PortableBackup{}, ErrInvalidCache
	}
	data, err := c.read()
	if err != nil {
		return PortableBackup{}, err
	}
	return PortableBackup{
		AccountID:             data.AccountID,
		Email:                 data.Email,
		PasswordVaultEnvelope: append([]byte(nil), data.PasswordVaultEnvelope...),
		Revisions:             cloneEncryptedRevisions(data.Revisions),
		Mutations:             cloneMutations(data.Mutations),
		Cursor:                data.Cursor,
	}, nil
}

// WritePortableBackupFileFromSnapshot writes a previously captured cache
// snapshot atomically, optionally adding semantic item values for v2 restore.
func (c *Cache) WritePortableBackupFileFromSnapshot(
	path string,
	backupPassword []byte,
	snapshot PortableBackup,
	items []NativeItem,
) error {
	if c == nil {
		return ErrInvalidCache
	}
	if items == nil {
		items = []NativeItem{}
	}
	data, err := portableBackupCacheData(snapshot)
	if err != nil {
		return err
	}
	return writePortableBackupFile(path, data, backupPassword, items)
}

func (c *Cache) writePortableBackupFile(
	path string,
	backupPassword []byte,
	items []NativeItem,
) error {
	if c == nil {
		return ErrInvalidCache
	}
	data, err := c.read()
	if err != nil {
		return err
	}
	return writePortableBackupFile(path, data, backupPassword, items)
}

func writePortableBackupFile(
	path string,
	data cacheFile,
	backupPassword []byte,
	items []NativeItem,
) error {
	if path == "" {
		return errors.New("backup path is required")
	}
	directory := filepath.Dir(path)
	file, err := os.CreateTemp(directory, ".termkeep-backup-*")
	if err != nil {
		return fmt.Errorf("create backup file: %w", err)
	}
	temporary := file.Name()
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporary)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return fmt.Errorf("restrict backup file: %w", err)
	}
	if err := writePortableBackup(file, data, backupPassword, items); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("flush backup file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close backup file: %w", err)
	}
	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("replace backup file: %w", err)
	}
	removeTemporary = false
	directoryFile, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open backup directory: %w", err)
	}
	defer directoryFile.Close()
	if err := directoryFile.Sync(); err != nil {
		return fmt.Errorf("flush backup directory: %w", err)
	}
	return nil
}

// ReadPortableBackup authenticates and opens a portable backup.
func ReadPortableBackup(
	reader io.Reader,
	backupPassword []byte,
) (PortableBackup, error) {
	if reader == nil || len(backupPassword) == 0 {
		return PortableBackup{}, ErrInvalidPortableBackup
	}
	encoded, err := io.ReadAll(io.LimitReader(
		reader,
		portableBackupMaxFileSize+1,
	))
	if err != nil || len(encoded) > portableBackupMaxFileSize {
		clearBytes(encoded)
		return PortableBackup{}, ErrInvalidPortableBackup
	}
	digest := sha256.Sum256(encoded)
	fingerprint := hex.EncodeToString(digest[:])
	defer clearBytes(encoded)
	var file portableBackupFile
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		return PortableBackup{}, ErrInvalidPortableBackup
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return PortableBackup{}, ErrInvalidPortableBackup
	}
	if !validPortableBackupFile(file) {
		return PortableBackup{}, ErrInvalidPortableBackup
	}
	canonical, err := json.Marshal(file)
	defer clearBytes(canonical)
	if err != nil || !bytes.Equal(encoded, canonical) {
		return PortableBackup{}, ErrInvalidPortableBackup
	}
	key := portableBackupKey(backupPassword, file.Salt)
	defer clearBytes(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return PortableBackup{}, ErrInvalidPortableBackup
	}
	plaintext, err := aead.Open(
		nil,
		file.Nonce,
		file.Ciphertext,
		portableBackupAssociatedData(file),
	)
	if err != nil {
		return PortableBackup{}, ErrInvalidPortableBackup
	}
	defer clearBytes(plaintext)
	var payload portableBackupPayload
	payloadDecoder := json.NewDecoder(bytes.NewReader(plaintext))
	payloadDecoder.DisallowUnknownFields()
	if err := payloadDecoder.Decode(&payload); err != nil {
		return PortableBackup{}, ErrInvalidPortableBackup
	}
	if err := payloadDecoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return PortableBackup{}, ErrInvalidPortableBackup
	}
	if file.Version != payload.Version || !validPortableBackupPayload(payload) {
		return PortableBackup{}, ErrInvalidPortableBackup
	}
	return PortableBackup{
		AccountID:             payload.AccountID,
		Email:                 payload.Email,
		PasswordVaultEnvelope: append([]byte(nil), payload.Envelope...),
		Revisions:             cloneEncryptedRevisions(payload.Revisions),
		Mutations:             cloneMutations(payload.Mutations),
		Cursor:                payload.Cursor,
		FormatVersion:         file.Version,
		Items:                 cloneNativeItems(payload.Items),
		Fingerprint:           fingerprint,
	}, nil
}

// ReadPortableBackupFile reads a mode-0600 portable backup file.
func ReadPortableBackupFile(
	path string,
	backupPassword []byte,
) (PortableBackup, error) {
	if path == "" {
		return PortableBackup{}, ErrInvalidPortableBackup
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 ||
		info.Size() > portableBackupMaxFileSize {
		return PortableBackup{}, ErrInvalidPortableBackup
	}
	file, err := os.Open(path)
	if err != nil {
		return PortableBackup{}, ErrInvalidPortableBackup
	}
	defer file.Close()
	return ReadPortableBackup(file, backupPassword)
}

func writePortableBackup(
	writer io.Writer,
	data cacheFile,
	backupPassword []byte,
	items []NativeItem,
) error {
	version := portableBackupLegacyVersion
	if items != nil {
		version = portableBackupFormatVersion
	}
	if version == portableBackupFormatVersion {
		expectedItems := 0
		for _, revisions := range data.Revisions {
			for _, item := range revisionHeads(revisions) {
				if !item.Deleted && !item.Purged {
					expectedItems++
				}
			}
		}
		if len(items) != expectedItems {
			return errors.New("portable backup semantic snapshot is incomplete")
		}
		for _, item := range items {
			if !validPortableBackupNativeItem(item) {
				return ErrInvalidItemEnvelope
			}
		}
	}
	payload, err := json.Marshal(portableBackupPayload{
		Version:   version,
		AccountID: data.AccountID,
		Email:     data.Email,
		Envelope:  data.PasswordVaultEnvelope,
		Revisions: data.Revisions,
		Mutations: data.Mutations,
		Cursor:    data.Cursor,
		Items:     items,
	})
	if err != nil {
		return fmt.Errorf("encode portable backup: %w", err)
	}
	defer clearBytes(payload)
	salt := make([]byte, portableBackupSaltSize)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("generate backup salt: %w", err)
	}
	key := portableBackupKey(backupPassword, salt)
	defer clearBytes(key)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return fmt.Errorf("initialize backup encryption: %w", err)
	}
	file := portableBackupFile{
		Magic:       portableBackupMagic,
		Version:     version,
		KDF:         portableBackupKDF,
		MemoryKiB:   portableBackupMemoryKiB,
		Passes:      portableBackupPasses,
		Parallelism: portableBackupParallelism,
		Salt:        salt,
		Nonce:       make([]byte, aead.NonceSize()),
	}
	if _, err := rand.Read(file.Nonce); err != nil {
		return fmt.Errorf("generate backup nonce: %w", err)
	}
	file.Ciphertext = aead.Seal(
		nil,
		file.Nonce,
		payload,
		portableBackupAssociatedData(file),
	)
	encoded, err := json.Marshal(file)
	if err != nil {
		return fmt.Errorf("encode backup header: %w", err)
	}
	if len(encoded) > portableBackupMaxFileSize {
		return errors.New("portable backup exceeds maximum file size")
	}
	written, err := writer.Write(encoded)
	if err != nil {
		return fmt.Errorf("write portable backup: %w", err)
	}
	if written != len(encoded) {
		return io.ErrShortWrite
	}
	return nil
}

func portableBackupCacheData(backup PortableBackup) (cacheFile, error) {
	if backup.AccountID == "" || backup.Email == "" ||
		len(backup.PasswordVaultEnvelope) == 0 || backup.Revisions == nil {
		return cacheFile{}, ErrInvalidPortableBackup
	}
	data := cacheFile{
		Version:               cacheFormatVersion,
		AccountID:             backup.AccountID,
		Email:                 backup.Email,
		PasswordVaultEnvelope: append([]byte(nil), backup.PasswordVaultEnvelope...),
		Revisions:             cloneEncryptedRevisions(backup.Revisions),
		Mutations:             cloneMutations(backup.Mutations),
		Cursor:                backup.Cursor,
	}
	if !validPortableBackupCacheData(data) {
		return cacheFile{}, ErrInvalidPortableBackup
	}
	return data, nil
}

func validPortableBackupFile(file portableBackupFile) bool {
	return file.Magic == portableBackupMagic &&
		(file.Version == portableBackupLegacyVersion ||
			file.Version == portableBackupFormatVersion) &&
		file.KDF == portableBackupKDF &&
		file.MemoryKiB == portableBackupMemoryKiB &&
		file.Passes == portableBackupPasses &&
		file.Parallelism == portableBackupParallelism &&
		len(file.Salt) == portableBackupSaltSize &&
		len(file.Nonce) == chacha20poly1305.NonceSizeX &&
		len(file.Ciphertext) > chacha20poly1305.Overhead
}

func validPortableBackupPayload(payload portableBackupPayload) bool {
	if (payload.Version != portableBackupLegacyVersion &&
		payload.Version != portableBackupFormatVersion) ||
		payload.AccountID == "" || payload.Email == "" ||
		len(payload.Envelope) == 0 || payload.Revisions == nil {
		return false
	}
	if payload.Version == portableBackupLegacyVersion && payload.Items != nil {
		return false
	}
	if payload.Version == portableBackupFormatVersion {
		expectedItems := 0
		for _, revisions := range payload.Revisions {
			for _, item := range revisionHeads(revisions) {
				if !item.Deleted && !item.Purged {
					expectedItems++
				}
			}
		}
		if (payload.Items == nil && expectedItems != 0) ||
			(payload.Items != nil && len(payload.Items) != expectedItems) {
			return false
		}
	}
	data := cacheFile{
		Version:               cacheFormatVersion,
		AccountID:             payload.AccountID,
		Email:                 payload.Email,
		PasswordVaultEnvelope: payload.Envelope,
		Revisions:             payload.Revisions,
		Mutations:             payload.Mutations,
		Cursor:                payload.Cursor,
	}
	if !validPortableBackupCacheData(data) {
		return false
	}
	for _, item := range payload.Items {
		if !validPortableBackupNativeItem(item) {
			return false
		}
	}
	return true
}

func validPortableBackupCacheData(data cacheFile) bool {
	return validateCacheData(data) == nil
}

func portableBackupKey(password, salt []byte) []byte {
	derived := argon2.IDKey(
		password,
		salt,
		portableBackupPasses,
		portableBackupMemoryKiB,
		portableBackupParallelism,
		chacha20poly1305.KeySize,
	)
	defer clearBytes(derived)
	return derivePurposeKey(derived, "portable-backup")
}

func portableBackupAssociatedData(file portableBackupFile) []byte {
	return []byte(fmt.Sprintf(
		"%s/v%d/%s/%d/%d/%d",
		file.Magic,
		file.Version,
		file.KDF,
		file.MemoryKiB,
		file.Passes,
		file.Parallelism,
	))
}

// ItemHeads returns every current head, including conflict heads.
func (backup PortableBackup) ItemHeads() []ItemHead {
	ids := make([]string, 0, len(backup.Revisions))
	for itemID := range backup.Revisions {
		ids = append(ids, itemID)
	}
	sort.Strings(ids)
	heads := make([]ItemHead, 0, len(ids))
	for _, itemID := range ids {
		current := revisionHeads(backup.Revisions[itemID])
		if len(current) != 0 {
			heads = append(heads, ItemHead{
				ItemID:    itemID,
				Revisions: current,
			})
		}
	}
	return heads
}

// ConflictCount reports the number of Item IDs with more than one head.
func (backup PortableBackup) ConflictCount() int {
	count := 0
	for _, revisions := range backup.Revisions {
		if len(revisionHeads(revisions)) > 1 {
			count++
		}
	}
	return count
}

// PreparePortableBackupImport gives restored records fresh IDs, remaps Folder
// references, and applies the common semantic duplicate naming pipeline.
func PreparePortableBackupImport(
	items []NativeItem,
	existing []NativeItem,
) (ImportPreview, error) {
	return preparePortableBackupImport(items, existing, "")
}

// PreparePortableBackupImportWithNamespace gives each source item a stable
// destination ID derived from namespace. Re-running an import for the same
// backup therefore produces no duplicate records.
func PreparePortableBackupImportWithNamespace(
	items []NativeItem,
	existing []NativeItem,
	namespace string,
) (ImportPreview, error) {
	if namespace == "" {
		return PreparePortableBackupImport(items, existing)
	}
	return preparePortableBackupImport(items, existing, namespace)
}

func preparePortableBackupImport(
	items []NativeItem,
	existing []NativeItem,
	namespace string,
) (ImportPreview, error) {
	prepared := make([]NativeItem, len(items))
	folderIDs := make(map[string]string)
	existingByID := make(map[string]NativeItem)
	if namespace != "" {
		for _, item := range existing {
			id, err := nativeItemID(item)
			if err != nil {
				return ImportPreview{}, err
			}
			if id != "" {
				existingByID[id] = item
			}
		}
	}
	for index, source := range items {
		item, err := cloneNativeItem(source)
		if err != nil {
			return ImportPreview{}, err
		}
		oldID, err := nativeItemID(item)
		if err != nil {
			return ImportPreview{}, err
		}
		newID := ""
		if namespace == "" {
			newID, err = NewItemID()
			if err != nil {
				return ImportPreview{}, err
			}
		} else {
			sourceKey := oldID
			if sourceKey == "" {
				encoded, marshalErr := json.Marshal(source)
				if marshalErr != nil {
					return ImportPreview{}, marshalErr
				}
				sourceKey = string(encoded)
			}
			newID = deterministicItemID(
				namespace,
				sourceKey+"\x00"+strconv.Itoa(index),
			)
		}
		if oldID != "" {
			if item.Type == NativeItemTypeFolder {
				if _, exists := folderIDs[oldID]; !exists {
					folderIDs[oldID] = newID
				}
			}
		}
		if err := setNativeItemID(&item, newID); err != nil {
			return ImportPreview{}, err
		}
		prepared[index] = item
	}
	for index := range prepared {
		if err := remapNativeFolderID(&prepared[index], folderIDs); err != nil {
			return ImportPreview{}, err
		}
	}
	preview := ImportPreview{}
	duplicates := importDuplicateCounts(existing)
	for index, item := range prepared {
		itemID, err := nativeItemID(item)
		if err != nil {
			return ImportPreview{}, err
		}
		if namespace != "" {
			if current, exists := existingByID[itemID]; exists {
				if sameNativeItem(current, item) {
					continue
				}
				preview.Errors = append(preview.Errors, ImportIssue{
					Item:    index + 1,
					Field:   "item_id",
					Message: "restored Item was changed locally; resolve the conflict before retrying",
				})
				continue
			}
		}
		nameImportDuplicate(&item, duplicates)
		preview.Items = append(preview.Items, item)
		switch item.Type {
		case NativeItemTypeLogin:
			preview.Counts.Logins++
		case NativeItemTypeSecureNote:
			preview.Counts.SecureNotes++
		case NativeItemTypeFolder:
			preview.Counts.Folders++
		case NativeItemTypeGeneric:
			preview.Counts.Generic++
		default:
			return ImportPreview{}, ErrInvalidItemEnvelope
		}
	}
	return preview, nil
}

func deterministicItemID(namespace, key string) string {
	digest := sha256.Sum256([]byte("termkeep/portable-import/" + namespace + "\x00" + key))
	value := append([]byte(nil), digest[:16]...)
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16])
}

// DeterministicItemID exposes the same stable UUID derivation to the command
// layer when it needs a deterministic revision ID for an imported item.
func DeterministicItemID(namespace, key string) string {
	if namespace == "" {
		return ""
	}
	return deterministicItemID(namespace, key)
}

func validPortableBackupNativeItem(item NativeItem) bool {
	id, err := nativeItemID(item)
	if err != nil || id == "" {
		return false
	}
	switch item.Type {
	case NativeItemTypeLogin:
		return item.Login != nil &&
			(item.Login.TOTP == nil || ValidateTOTPConfig(*item.Login.TOTP) == nil)
	case NativeItemTypeSecureNote:
		return item.SecureNote != nil
	case NativeItemTypeFolder:
		return item.Folder != nil
	case NativeItemTypeGeneric:
		return item.Generic != nil && item.Generic.Title != "" &&
			item.Generic.Source != "" && item.Generic.SourceType != "" &&
			json.Valid(item.Generic.Data)
	default:
		return false
	}
}

func cloneNativeItems(items []NativeItem) []NativeItem {
	if items == nil {
		return nil
	}
	clone := make([]NativeItem, len(items))
	for index, item := range items {
		cloned, err := cloneNativeItem(item)
		if err != nil {
			return nil
		}
		clone[index] = cloned
	}
	return clone
}

func sameNativeItem(left, right NativeItem) bool {
	left = restoreComparisonItem(left)
	right = restoreComparisonItem(right)
	leftEncoded, leftErr := json.Marshal(left)
	rightEncoded, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil &&
		bytes.Equal(leftEncoded, rightEncoded)
}

func restoreComparisonItem(item NativeItem) NativeItem {
	clone, err := cloneNativeItem(item)
	if err != nil {
		return NativeItem{}
	}
	switch clone.Type {
	case NativeItemTypeLogin:
		if clone.Login != nil {
			clone.Login.Name = ""
		}
	case NativeItemTypeSecureNote:
		if clone.SecureNote != nil {
			clone.SecureNote.Title = ""
		}
	case NativeItemTypeFolder:
		if clone.Folder != nil {
			clone.Folder.Name = ""
		}
	case NativeItemTypeGeneric:
		if clone.Generic != nil {
			clone.Generic.Title = ""
		}
	}
	return clone
}

func cloneEncryptedRevisions(
	revisions map[string]map[string]EncryptedItem,
) map[string]map[string]EncryptedItem {
	clone := make(map[string]map[string]EncryptedItem, len(revisions))
	for itemID, values := range revisions {
		clone[itemID] = make(map[string]EncryptedItem, len(values))
		for revisionID, item := range values {
			clone[itemID][revisionID] = cloneEncryptedItem(item)
		}
	}
	return clone
}

func cloneMutations(mutations []Mutation) []Mutation {
	clone := make([]Mutation, len(mutations))
	for index, mutation := range mutations {
		clone[index] = cloneMutation(mutation)
	}
	return clone
}

func cloneNativeItem(item NativeItem) (NativeItem, error) {
	encoded, err := json.Marshal(item)
	if err != nil {
		return NativeItem{}, err
	}
	var clone NativeItem
	if err := json.Unmarshal(encoded, &clone); err != nil {
		return NativeItem{}, err
	}
	return clone, nil
}

func nativeItemID(item NativeItem) (string, error) {
	switch item.Type {
	case NativeItemTypeLogin:
		if item.Login == nil {
			return "", ErrInvalidItemEnvelope
		}
		return item.Login.ItemID, nil
	case NativeItemTypeSecureNote:
		if item.SecureNote == nil {
			return "", ErrInvalidItemEnvelope
		}
		return item.SecureNote.ItemID, nil
	case NativeItemTypeFolder:
		if item.Folder == nil {
			return "", ErrInvalidItemEnvelope
		}
		return item.Folder.ItemID, nil
	case NativeItemTypeGeneric:
		if item.Generic == nil {
			return "", ErrInvalidItemEnvelope
		}
		return item.Generic.ItemID, nil
	default:
		return "", ErrInvalidItemEnvelope
	}
}

func setNativeItemID(item *NativeItem, itemID string) error {
	switch item.Type {
	case NativeItemTypeLogin:
		if item.Login == nil {
			return ErrInvalidItemEnvelope
		}
		item.Login.ItemID = itemID
	case NativeItemTypeSecureNote:
		if item.SecureNote == nil {
			return ErrInvalidItemEnvelope
		}
		item.SecureNote.ItemID = itemID
	case NativeItemTypeFolder:
		if item.Folder == nil {
			return ErrInvalidItemEnvelope
		}
		item.Folder.ItemID = itemID
	case NativeItemTypeGeneric:
		if item.Generic == nil {
			return ErrInvalidItemEnvelope
		}
		item.Generic.ItemID = itemID
	default:
		return ErrInvalidItemEnvelope
	}
	return nil
}

func remapNativeFolderID(
	item *NativeItem,
	folderIDs map[string]string,
) error {
	var folderID *string
	switch item.Type {
	case NativeItemTypeLogin:
		if item.Login == nil {
			return ErrInvalidItemEnvelope
		}
		folderID = &item.Login.FolderID
	case NativeItemTypeSecureNote:
		if item.SecureNote == nil {
			return ErrInvalidItemEnvelope
		}
		folderID = &item.SecureNote.FolderID
	case NativeItemTypeGeneric:
		if item.Generic == nil {
			return ErrInvalidItemEnvelope
		}
		folderID = &item.Generic.FolderID
	case NativeItemTypeFolder:
		return nil
	default:
		return ErrInvalidItemEnvelope
	}
	if mapped, ok := folderIDs[*folderID]; ok {
		*folderID = mapped
	} else if *folderID != "" {
		// A deleted or purged source folder is not part of semantic Items;
		// never leave a dangling source UUID in the destination Vault.
		*folderID = ""
	}
	return nil
}
