package client

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

const cacheFormatVersion = 1
const maximumCacheFileSize = 64 << 20

var ErrCacheNotFound = errors.New("authorized cache not found")
var ErrInvalidCache = errors.New("invalid encrypted cache")

type cacheFile struct {
	Version               int                      `json:"version"`
	AccountID             string                   `json:"account_id"`
	Email                 string                   `json:"email"`
	PasswordVaultEnvelope []byte                   `json:"password_vault_envelope"`
	Items                 map[string]EncryptedItem `json:"items"`
	Mutations             []Mutation               `json:"mutations"`
	Cursor                string                   `json:"cursor"`
}

type Mutation struct {
	MutationID   string        `json:"mutation_id"`
	BaseRevision uint64        `json:"base_revision"`
	Item         EncryptedItem `json:"item"`
}

type SyncSnapshot struct {
	Cursor    string
	Mutations []Mutation
}

type Cache struct {
	path string
}

func AuthorizeCache(
	cfg Config,
	email string,
	accountID string,
	passwordVaultEnvelope []byte,
) error {
	email, err := canonicalBootstrapEmail(email)
	if err != nil {
		return err
	}
	if accountID == "" || len(passwordVaultEnvelope) == 0 {
		return ErrInvalidCache
	}
	path, err := cachePath(cfg, email)
	if err != nil {
		return err
	}
	data := cacheFile{
		Version:               cacheFormatVersion,
		AccountID:             accountID,
		Email:                 email,
		PasswordVaultEnvelope: append([]byte(nil), passwordVaultEnvelope...),
		Items:                 make(map[string]EncryptedItem),
	}
	return withCacheLock(path, true, func() error {
		if existing, err := readCacheFile(path); err == nil {
			if existing.AccountID != accountID || existing.Email != email {
				return ErrInvalidCache
			}
			data = existing
			data.PasswordVaultEnvelope = append(
				data.PasswordVaultEnvelope[:0], passwordVaultEnvelope...)
		} else if !errors.Is(err, ErrCacheNotFound) {
			return err
		}
		return writeCacheFile(path, data)
	})
}

func OpenCache(cfg Config, email string) (*Cache, error) {
	email, err := canonicalBootstrapEmail(email)
	if err != nil {
		return nil, err
	}
	path, err := cachePath(cfg, email)
	if err != nil {
		return nil, err
	}
	if _, err := readCacheFile(path); err != nil {
		return nil, err
	}
	return &Cache{path: path}, nil
}

func (c *Cache) Path() string {
	return c.path
}

func (c *Cache) Unlock(masterPassword []byte) ([]byte, error) {
	data, err := c.read()
	if err != nil {
		return nil, err
	}
	return UnlockVaultWithPassword(
		data.PasswordVaultEnvelope, masterPassword, data.AccountID)
}

func (c *Cache) QueueMutation(
	item EncryptedItem,
	baseRevision uint64,
) (Mutation, error) {
	if item.ItemID == "" || item.SchemaVersion < 1 ||
		item.Revision == 0 || item.Revision != baseRevision+1 ||
		len(item.Envelope) == 0 {
		return Mutation{}, ErrInvalidItemEnvelope
	}
	mutationID, err := NewItemID()
	if err != nil {
		return Mutation{}, err
	}
	mutation := Mutation{
		MutationID:   mutationID,
		BaseRevision: baseRevision,
		Item:         cloneEncryptedItem(item),
	}
	err = withCacheLock(c.path, true, func() error {
		data, err := readCacheFile(c.path)
		if err != nil {
			return err
		}
		current, exists := data.Items[item.ItemID]
		if (!exists && baseRevision != 0) ||
			(exists && current.Revision != baseRevision) {
			return errors.New("local item revision conflict")
		}
		data.Items[item.ItemID] = cloneEncryptedItem(item)
		data.Mutations = append(data.Mutations, mutation)
		return writeCacheFile(c.path, data)
	})
	if err != nil {
		return Mutation{}, err
	}
	return mutation, nil
}

func (c *Cache) Items() ([]EncryptedItem, error) {
	data, err := c.read()
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(data.Items))
	for itemID := range data.Items {
		ids = append(ids, itemID)
	}
	sort.Strings(ids)
	items := make([]EncryptedItem, 0, len(ids))
	for _, itemID := range ids {
		items = append(items, cloneEncryptedItem(data.Items[itemID]))
	}
	return items, nil
}

func (c *Cache) PendingMutations() ([]Mutation, error) {
	data, err := c.read()
	if err != nil {
		return nil, err
	}
	mutations := make([]Mutation, len(data.Mutations))
	for index, mutation := range data.Mutations {
		mutations[index] = cloneMutation(mutation)
	}
	return mutations, nil
}

func (c *Cache) SyncSnapshot() (SyncSnapshot, error) {
	data, err := c.read()
	if err != nil {
		return SyncSnapshot{}, err
	}
	snapshot := SyncSnapshot{Cursor: data.Cursor}
	snapshot.Mutations = make([]Mutation, len(data.Mutations))
	for index, mutation := range data.Mutations {
		snapshot.Mutations[index] = cloneMutation(mutation)
	}
	return snapshot, nil
}

func (c *Cache) ApplySync(
	cursor string,
	appliedMutationIDs []string,
	changes []EncryptedItem,
) error {
	if _, err := strconv.ParseUint(cursor, 10, 63); err != nil {
		return errors.New("invalid synchronization cursor")
	}
	applied := make(map[string]bool, len(appliedMutationIDs))
	for _, mutationID := range appliedMutationIDs {
		if mutationID == "" {
			return errors.New("invalid applied mutation ID")
		}
		applied[mutationID] = true
	}
	for _, change := range changes {
		if change.ItemID == "" || change.SchemaVersion < 1 ||
			change.Revision < 1 || len(change.Envelope) == 0 {
			return ErrInvalidItemEnvelope
		}
	}
	return withCacheLock(c.path, true, func() error {
		data, err := readCacheFile(c.path)
		if err != nil {
			return err
		}
		pending := data.Mutations[:0]
		for _, mutation := range data.Mutations {
			if !applied[mutation.MutationID] {
				pending = append(pending, mutation)
			}
		}
		data.Mutations = pending
		for _, change := range changes {
			current, exists := data.Items[change.ItemID]
			if !exists || change.Revision >= current.Revision {
				data.Items[change.ItemID] = cloneEncryptedItem(change)
			}
		}
		data.Cursor = cursor
		return writeCacheFile(c.path, data)
	})
}

func (c *Cache) read() (cacheFile, error) {
	var data cacheFile
	err := withCacheLock(c.path, false, func() error {
		var err error
		data, err = readCacheFile(c.path)
		return err
	})
	return data, err
}

func cachePath(cfg Config, email string) (string, error) {
	directory, err := cacheDirectory(cfg)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(email))
	return filepath.Join(directory, fmt.Sprintf("%x.json", digest)), nil
}

func cacheDirectory(cfg Config) (string, error) {
	directory := cfg.DataDir
	if directory == "" {
		if dataHome := os.Getenv("XDG_DATA_HOME"); dataHome != "" {
			directory = filepath.Join(dataHome, "termkeep")
		} else {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", fmt.Errorf("locate cache directory: %w", err)
			}
			directory = filepath.Join(home, ".local", "share", "termkeep")
		}
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", fmt.Errorf("create cache directory: %w", err)
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return "", fmt.Errorf("inspect cache directory: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o077 != 0 ||
		!ok || stat.Uid != uint32(os.Getuid()) {
		return "", errors.New("cache directory must be private and owned by the current user")
	}
	return directory, nil
}

func readCacheFile(path string) (cacheFile, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return cacheFile{}, ErrCacheNotFound
	}
	if err != nil {
		return cacheFile{}, fmt.Errorf("inspect encrypted cache: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 ||
		info.Size() > maximumCacheFileSize {
		return cacheFile{}, ErrInvalidCache
	}
	file, err := os.Open(path)
	if err != nil {
		return cacheFile{}, fmt.Errorf("open encrypted cache: %w", err)
	}
	defer file.Close()
	var data cacheFile
	decoder := json.NewDecoder(io.LimitReader(file, maximumCacheFileSize+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&data); err != nil {
		return cacheFile{}, ErrInvalidCache
	}
	if data.Version != cacheFormatVersion ||
		data.AccountID == "" ||
		data.Email == "" ||
		len(data.PasswordVaultEnvelope) == 0 {
		return cacheFile{}, ErrInvalidCache
	}
	if data.Items == nil {
		data.Items = make(map[string]EncryptedItem)
	}
	for itemID, item := range data.Items {
		if itemID == "" || item.ItemID != itemID ||
			item.SchemaVersion < 1 || item.Revision < 1 ||
			len(item.Envelope) == 0 {
			return cacheFile{}, ErrInvalidCache
		}
	}
	for _, mutation := range data.Mutations {
		if mutation.MutationID == "" ||
			mutation.Item.Revision != mutation.BaseRevision+1 ||
			mutation.Item.ItemID == "" ||
			len(mutation.Item.Envelope) == 0 {
			return cacheFile{}, ErrInvalidCache
		}
	}
	return data, nil
}

func writeCacheFile(path string, data cacheFile) error {
	encoded, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("encode encrypted cache: %w", err)
	}
	directory := filepath.Dir(path)
	file, err := os.CreateTemp(directory, ".termkeep-cache-*")
	if err != nil {
		return fmt.Errorf("create encrypted cache: %w", err)
	}
	tempPath := file.Name()
	defer os.Remove(tempPath)
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return fmt.Errorf("restrict encrypted cache: %w", err)
	}
	if _, err := file.Write(encoded); err != nil {
		file.Close()
		return fmt.Errorf("write encrypted cache: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return fmt.Errorf("flush encrypted cache: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close encrypted cache: %w", err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("replace encrypted cache: %w", err)
	}
	directoryFile, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open cache directory: %w", err)
	}
	defer directoryFile.Close()
	if err := directoryFile.Sync(); err != nil {
		return fmt.Errorf("flush cache directory: %w", err)
	}
	return nil
}

func withCacheLock(path string, exclusive bool, operation func() error) error {
	flags := unix.O_CREAT | unix.O_RDWR | unix.O_CLOEXEC | unix.O_NOFOLLOW
	fd, err := unix.Open(path+".lock", flags, 0o600)
	if err != nil {
		return fmt.Errorf("open cache lock: %w", err)
	}
	lock := os.NewFile(uintptr(fd), path+".lock")
	defer lock.Close()
	kind := unix.LOCK_SH
	if exclusive {
		kind = unix.LOCK_EX
	}
	if err := unix.Flock(fd, kind); err != nil {
		return fmt.Errorf("lock encrypted cache: %w", err)
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	return operation()
}

func cloneEncryptedItem(item EncryptedItem) EncryptedItem {
	item.Envelope = append([]byte(nil), item.Envelope...)
	return item
}

func cloneMutation(mutation Mutation) Mutation {
	mutation.Item = cloneEncryptedItem(mutation.Item)
	return mutation
}
