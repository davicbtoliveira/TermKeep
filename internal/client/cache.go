package client

import (
	"bytes"
	"crypto/md5"
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

const cacheFormatVersion = 2
const legacyCacheFormatVersion = 1
const maximumCacheFileSize = 64 << 20

var ErrCacheNotFound = errors.New("authorized cache not found")
var ErrInvalidCache = errors.New("invalid encrypted cache")

type cacheFile struct {
	Version               int                                 `json:"version"`
	AccountID             string                              `json:"account_id"`
	Email                 string                              `json:"email"`
	PasswordVaultEnvelope []byte                              `json:"password_vault_envelope"`
	Items                 map[string]EncryptedItem            `json:"items,omitempty"`
	Revisions             map[string]map[string]EncryptedItem `json:"revisions"`
	Mutations             []Mutation                          `json:"mutations"`
	Cursor                string                              `json:"cursor"`
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

type ItemHead struct {
	ItemID    string
	Revisions []EncryptedItem
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
		Revisions:             make(map[string]map[string]EncryptedItem),
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
	if item.RevisionID == "" {
		revisionID, err := NewItemID()
		if err != nil {
			return Mutation{}, err
		}
		item.RevisionID = revisionID
	}
	var mutation Mutation
	err := withCacheLock(c.path, true, func() error {
		data, err := readCacheFile(c.path)
		if err != nil {
			return err
		}
		revisions := data.Revisions[item.ItemID]
		if revisions == nil {
			revisions = make(map[string]EncryptedItem)
			data.Revisions[item.ItemID] = revisions
		}
		if baseRevision == 0 {
			if len(revisions) != 0 ||
				len(item.ParentRevisionIDs) != 0 {
				return errors.New("local item revision conflict")
			}
		} else {
			if len(item.ParentRevisionIDs) == 0 {
				heads := revisionHeads(revisions)
				for _, head := range heads {
					if head.Revision == baseRevision {
						item.ParentRevisionIDs = append(
							item.ParentRevisionIDs, head.RevisionID)
					}
				}
				if len(item.ParentRevisionIDs) != 1 {
					return errors.New("local item revision conflict")
				}
			}
			sort.Strings(item.ParentRevisionIDs)
			var maxParentRevision uint64
			seen := make(map[string]bool, len(item.ParentRevisionIDs))
			for _, parentID := range item.ParentRevisionIDs {
				parent, exists := revisions[parentID]
				if !exists || seen[parentID] {
					return errors.New("local item revision conflict")
				}
				seen[parentID] = true
				maxParentRevision = max(
					maxParentRevision, parent.Revision)
			}
			if maxParentRevision != baseRevision {
				return errors.New("local item revision conflict")
			}
		}
		if _, exists := revisions[item.RevisionID]; exists {
			return errors.New("local revision ID already exists")
		}
		item = cloneEncryptedItem(item)
		mutation = Mutation{
			MutationID:   item.RevisionID,
			BaseRevision: baseRevision,
			Item:         item,
		}
		revisions[item.RevisionID] = item
		data.Mutations = append(data.Mutations, mutation)
		return writeCacheFile(c.path, data)
	})
	if err != nil {
		return Mutation{}, err
	}
	return mutation, nil
}

func (c *Cache) Items() ([]EncryptedItem, error) {
	groups, err := c.ItemHeads()
	if err != nil {
		return nil, err
	}
	var items []EncryptedItem
	for _, group := range groups {
		items = append(items, group.Revisions...)
	}
	return items, nil
}

func (c *Cache) ItemHeads() ([]ItemHead, error) {
	data, err := c.read()
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(data.Revisions))
	for itemID := range data.Revisions {
		ids = append(ids, itemID)
	}
	sort.Strings(ids)
	groups := make([]ItemHead, 0, len(ids))
	for _, itemID := range ids {
		heads := revisionHeads(data.Revisions[itemID])
		if len(heads) == 0 {
			continue
		}
		groups = append(groups, ItemHead{
			ItemID:    itemID,
			Revisions: heads,
		})
	}
	return groups, nil
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
			change.Revision < 1 || change.RevisionID == "" ||
			len(change.Envelope) == 0 {
			return ErrInvalidItemEnvelope
		}
		seen := make(map[string]bool, len(change.ParentRevisionIDs))
		for _, parentID := range change.ParentRevisionIDs {
			if parentID == "" || seen[parentID] {
				return ErrInvalidItemEnvelope
			}
			seen[parentID] = true
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
			revisions := data.Revisions[change.ItemID]
			if revisions == nil {
				revisions = make(map[string]EncryptedItem)
				data.Revisions[change.ItemID] = revisions
			}
			current, exists := revisions[change.RevisionID]
			if exists && !sameEncryptedItem(current, change) {
				return ErrInvalidItemEnvelope
			}
			revisions[change.RevisionID] = cloneEncryptedItem(change)
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
	if (data.Version != cacheFormatVersion &&
		data.Version != legacyCacheFormatVersion) ||
		data.AccountID == "" ||
		data.Email == "" ||
		len(data.PasswordVaultEnvelope) == 0 {
		return cacheFile{}, ErrInvalidCache
	}
	if data.Version == legacyCacheFormatVersion {
		if err := migrateLegacyCache(&data); err != nil {
			return cacheFile{}, err
		}
	}
	if data.Revisions == nil {
		data.Revisions = make(
			map[string]map[string]EncryptedItem)
	}
	for itemID, revisions := range data.Revisions {
		if itemID == "" || revisions == nil {
			return cacheFile{}, ErrInvalidCache
		}
		for revisionID, item := range revisions {
			if revisionID == "" || item.RevisionID != revisionID ||
				item.ItemID != itemID || item.SchemaVersion < 1 ||
				item.Revision < 1 || len(item.Envelope) == 0 ||
				hasInvalidParentIDs(item.ParentRevisionIDs) {
				return cacheFile{}, ErrInvalidCache
			}
		}
	}
	for _, mutation := range data.Mutations {
		if mutation.MutationID == "" ||
			mutation.Item.RevisionID != mutation.MutationID ||
			mutation.Item.Revision != mutation.BaseRevision+1 ||
			mutation.Item.ItemID == "" ||
			len(mutation.Item.Envelope) == 0 ||
			(mutation.BaseRevision == 0 &&
				len(mutation.Item.ParentRevisionIDs) != 0) ||
			(mutation.BaseRevision > 0 &&
				len(mutation.Item.ParentRevisionIDs) == 0) ||
			hasInvalidParentIDs(mutation.Item.ParentRevisionIDs) {
			return cacheFile{}, ErrInvalidCache
		}
	}
	return data, nil
}

func migrateLegacyCache(data *cacheFile) error {
	if data.Items == nil {
		data.Items = make(map[string]EncryptedItem)
	}
	data.Revisions = make(
		map[string]map[string]EncryptedItem)
	pending := make(map[string]bool, len(data.Mutations))
	for _, mutation := range data.Mutations {
		if mutation.MutationID == "" ||
			mutation.Item.ItemID == "" ||
			mutation.Item.Revision != mutation.BaseRevision+1 ||
			len(mutation.Item.Envelope) == 0 {
			return ErrInvalidCache
		}
		pending[fmt.Sprintf(
			"%s:%d", mutation.Item.ItemID, mutation.Item.Revision)] = true
	}
	known := make(map[string]map[uint64]string)
	for itemID, item := range data.Items {
		if itemID == "" || item.ItemID != itemID ||
			item.SchemaVersion < 1 || item.Revision < 1 ||
			len(item.Envelope) == 0 {
			return ErrInvalidCache
		}
		if pending[fmt.Sprintf("%s:%d", itemID, item.Revision)] {
			continue
		}
		item.RevisionID = legacyRevisionID(
			data.AccountID, itemID, item.Revision)
		addCachedRevision(data, item)
		if known[itemID] == nil {
			known[itemID] = make(map[uint64]string)
		}
		known[itemID][item.Revision] = item.RevisionID
	}
	for index := range data.Mutations {
		mutation := &data.Mutations[index]
		item := cloneEncryptedItem(mutation.Item)
		item.RevisionID = mutation.MutationID
		if mutation.BaseRevision > 0 {
			parentID := known[item.ItemID][mutation.BaseRevision]
			if parentID == "" {
				parentID = legacyRevisionID(
					data.AccountID, item.ItemID, mutation.BaseRevision)
			}
			item.ParentRevisionIDs = []string{parentID}
		}
		mutation.Item = item
		addCachedRevision(data, item)
		if known[item.ItemID] == nil {
			known[item.ItemID] = make(map[uint64]string)
		}
		known[item.ItemID][item.Revision] = item.RevisionID
	}
	data.Version = cacheFormatVersion
	data.Items = nil
	return nil
}

func writeCacheFile(path string, data cacheFile) error {
	data.Version = cacheFormatVersion
	data.Items = nil
	if data.Revisions == nil {
		data.Revisions = make(
			map[string]map[string]EncryptedItem)
	}
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
	item.ParentRevisionIDs = append(
		[]string(nil), item.ParentRevisionIDs...)
	item.Envelope = append([]byte(nil), item.Envelope...)
	return item
}

func cloneMutation(mutation Mutation) Mutation {
	mutation.Item = cloneEncryptedItem(mutation.Item)
	return mutation
}

func addCachedRevision(data *cacheFile, item EncryptedItem) {
	if data.Revisions[item.ItemID] == nil {
		data.Revisions[item.ItemID] =
			make(map[string]EncryptedItem)
	}
	data.Revisions[item.ItemID][item.RevisionID] =
		cloneEncryptedItem(item)
}

func revisionHeads(
	revisions map[string]EncryptedItem,
) []EncryptedItem {
	referenced := make(map[string]bool)
	for _, revision := range revisions {
		for _, parentID := range revision.ParentRevisionIDs {
			referenced[parentID] = true
		}
	}
	ids := make([]string, 0, len(revisions))
	for revisionID := range revisions {
		if !referenced[revisionID] {
			ids = append(ids, revisionID)
		}
	}
	sort.Strings(ids)
	heads := make([]EncryptedItem, 0, len(ids))
	for _, revisionID := range ids {
		heads = append(
			heads, cloneEncryptedItem(revisions[revisionID]))
	}
	return heads
}

func sameEncryptedItem(left, right EncryptedItem) bool {
	if left.ItemID != right.ItemID ||
		left.SchemaVersion != right.SchemaVersion ||
		left.Revision != right.Revision ||
		left.RevisionID != right.RevisionID ||
		!bytes.Equal(left.Envelope, right.Envelope) ||
		len(left.ParentRevisionIDs) != len(right.ParentRevisionIDs) {
		return false
	}
	leftParents := append([]string(nil), left.ParentRevisionIDs...)
	rightParents := append([]string(nil), right.ParentRevisionIDs...)
	sort.Strings(leftParents)
	sort.Strings(rightParents)
	for index := range leftParents {
		if leftParents[index] != rightParents[index] {
			return false
		}
	}
	return true
}

func hasInvalidParentIDs(ids []string) bool {
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if id == "" || seen[id] {
			return true
		}
		seen[id] = true
	}
	return false
}

func legacyRevisionID(
	accountID string,
	itemID string,
	revision uint64,
) string {
	digest := md5.Sum([]byte(fmt.Sprintf(
		"%s:%s:%d", accountID, itemID, revision)))
	encoded := fmt.Sprintf("%x", digest)
	return fmt.Sprintf(
		"%s-%s-%s-%s-%s",
		encoded[0:8],
		encoded[8:12],
		encoded[12:16],
		encoded[16:20],
		encoded[20:32],
	)
}
