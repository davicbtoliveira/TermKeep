package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthenticatedAccountStoresAndListsOpaqueItem(t *testing.T) {
	authStore := &memoryBootstrapStore{}
	auth := newTestAuthService(t, authStore)
	itemStore := &memoryItemStore{}
	items := NewItemService(itemStore, auth)
	handler := NewHandler("test", stubSchema{version: 1}, nil, auth, items)
	server := httptest.NewServer(handler)
	defer server.Close()

	password := []byte("TermKeep#2026")
	mustBootstrap(t, server, "admin@example.com", password)
	token := mustLogin(t, server, "admin@example.com", password)
	itemID := "11111111-1111-4111-8111-111111111111"
	envelope := []byte{0xde, 0xad, 0xbe, 0xef}

	requestBody, err := json.Marshal(map[string]any{
		"schema_version": 1,
		"revision":       1,
		"envelope":       envelope,
	})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(
		http.MethodPut,
		server.URL+"/api/v1/items/"+itemID,
		bytes.NewReader(requestBody),
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("store item status: want 204, got %d", response.StatusCode)
	}

	listResponse := getJSONWithAuth(t, server.URL+"/api/v1/items", token)
	if listResponse.StatusCode != http.StatusOK {
		t.Fatalf("list items status: want 200, got %d", listResponse.StatusCode)
	}
	var body struct {
		Items []OpaqueItem `json:"items"`
	}
	decodeJSON(t, listResponse, &body)
	if len(body.Items) != 1 {
		t.Fatalf("items: want 1, got %d", len(body.Items))
	}
	item := body.Items[0]
	if item.ItemID != itemID || item.SchemaVersion != 1 ||
		item.Revision != 1 || !bytes.Equal(item.Envelope, envelope) {
		t.Fatalf("opaque item changed: %+v", item)
	}
}

func TestOpaqueItemRejectsStaleRevision(t *testing.T) {
	authStore := &memoryBootstrapStore{}
	auth := newTestAuthService(t, authStore)
	itemStore := &memoryItemStore{}
	items := NewItemService(itemStore, auth)
	handler := NewHandler("test", stubSchema{version: 1}, nil, auth, items)
	server := httptest.NewServer(handler)
	defer server.Close()

	password := []byte("TermKeep#2026")
	mustBootstrap(t, server, "admin@example.com", password)
	token := mustLogin(t, server, "admin@example.com", password)
	itemID := "11111111-1111-4111-8111-111111111111"

	first := putOpaqueItem(t, server, token, itemID, 1, []byte("first"))
	first.Body.Close()
	if first.StatusCode != http.StatusNoContent {
		t.Fatalf("first revision status: want 204, got %d", first.StatusCode)
	}
	stale := putOpaqueItem(t, server, token, itemID, 1, []byte("stale"))
	stale.Body.Close()
	if stale.StatusCode != http.StatusConflict {
		t.Fatalf("stale revision status: want 409, got %d", stale.StatusCode)
	}
	stored := itemStore.items[authStore.account.AccountID][itemID]
	if !bytes.Equal(stored.Envelope, []byte("first")) {
		t.Fatalf("stale revision overwrote item: %q", stored.Envelope)
	}
}

func TestSyncPushesMutationAndReturnsChangeCursor(t *testing.T) {
	authStore := &memoryBootstrapStore{}
	auth := newTestAuthService(t, authStore)
	itemStore := &memoryItemStore{}
	items := NewItemService(itemStore, auth)
	handler := NewHandler("test", stubSchema{version: 1}, nil, auth, items)
	server := httptest.NewServer(handler)
	defer server.Close()

	password := []byte("TermKeep#2026")
	mustBootstrap(t, server, "admin@example.com", password)
	token := mustLogin(t, server, "admin@example.com", password)
	itemID := "11111111-1111-4111-8111-111111111111"
	mutationID := "22222222-2222-4222-8222-222222222222"
	body := syncOpaqueItems(t, server, token, "", []VaultMutation{{
		MutationID:   mutationID,
		BaseRevision: 0,
		Item: OpaqueItem{
			ItemID:        itemID,
			SchemaVersion: 1,
			Revision:      1,
			Envelope:      []byte("encrypted"),
		},
	}})

	if body.Cursor == "" {
		t.Fatal("sync returned empty cursor")
	}
	if len(body.AppliedMutationIDs) != 1 ||
		body.AppliedMutationIDs[0] != mutationID {
		t.Fatalf("applied mutations: %+v", body.AppliedMutationIDs)
	}
	if len(body.Changes) != 1 ||
		body.Changes[0].ItemID != itemID ||
		body.Changes[0].Revision != 1 ||
		!bytes.Equal(body.Changes[0].Envelope, []byte("encrypted")) {
		t.Fatalf("sync changes: %+v", body.Changes)
	}
}

func TestSyncPreservesConcurrentRevisions(t *testing.T) {
	authStore := &memoryBootstrapStore{}
	auth := newTestAuthService(t, authStore)
	itemStore := &memoryItemStore{}
	items := NewItemService(itemStore, auth)
	handler := NewHandler("test", stubSchema{version: 1}, nil, auth, items)
	server := httptest.NewServer(handler)
	defer server.Close()

	password := []byte("TermKeep#2026")
	mustBootstrap(t, server, "admin@example.com", password)
	token := mustLogin(t, server, "admin@example.com", password)
	itemID := "11111111-1111-4111-8111-111111111111"
	rootID := "22222222-2222-4222-8222-222222222222"
	root := VaultMutation{
		MutationID:   rootID,
		BaseRevision: 0,
		Item: OpaqueItem{
			ItemID:        itemID,
			SchemaVersion: 1,
			Revision:      1,
			RevisionID:    rootID,
			Envelope:      []byte("root"),
		},
	}
	rootResult := syncOpaqueItems(
		t, server, token, "", []VaultMutation{root})

	firstID := "33333333-3333-4333-8333-333333333333"
	secondID := "44444444-4444-4444-8444-444444444444"
	first := VaultMutation{
		MutationID:   firstID,
		BaseRevision: 1,
		Item: OpaqueItem{
			ItemID:            itemID,
			SchemaVersion:     1,
			Revision:          2,
			RevisionID:        firstID,
			ParentRevisionIDs: []string{rootID},
			Envelope:          []byte("first"),
		},
	}
	second := VaultMutation{
		MutationID:   secondID,
		BaseRevision: 1,
		Item: OpaqueItem{
			ItemID:            itemID,
			SchemaVersion:     1,
			Revision:          2,
			RevisionID:        secondID,
			ParentRevisionIDs: []string{rootID},
			Envelope:          []byte("second"),
		},
	}
	syncOpaqueItems(t, server, token, rootResult.Cursor, []VaultMutation{first})
	syncOpaqueItems(t, server, token, rootResult.Cursor, []VaultMutation{second})

	pulled := syncOpaqueItems(t, server, token, rootResult.Cursor, nil)
	if len(pulled.Changes) != 2 {
		t.Fatalf("concurrent revisions: want 2, got %+v", pulled.Changes)
	}
	got := map[string]string{}
	for _, revision := range pulled.Changes {
		got[revision.RevisionID] = string(revision.Envelope)
	}
	if got[firstID] != "first" || got[secondID] != "second" {
		t.Fatalf("concurrent revisions were not preserved: %+v", got)
	}
}

func TestSyncAcceptsEncryptedTrashRevision(t *testing.T) {
	authStore := &memoryBootstrapStore{}
	auth := newTestAuthService(t, authStore)
	itemStore := &memoryItemStore{}
	items := NewItemService(itemStore, auth)
	handler := NewHandler("test", stubSchema{version: 1}, nil, auth, items)
	testServer := httptest.NewServer(handler)
	defer testServer.Close()

	password := []byte("TermKeep#2026")
	mustBootstrap(t, testServer, "admin@example.com", password)
	token := mustLogin(t, testServer, "admin@example.com", password)
	itemID := "11111111-1111-4111-8111-111111111111"
	rootID := "22222222-2222-4222-8222-222222222222"
	root := VaultMutation{
		MutationID:   rootID,
		BaseRevision: 0,
		Item: OpaqueItem{
			ItemID:        itemID,
			SchemaVersion: 1,
			Revision:      1,
			RevisionID:    rootID,
			Envelope:      []byte("encrypted-root"),
		},
	}
	rootResult := syncOpaqueItems(
		t, testServer, token, "", []VaultMutation{root})
	deletionID := "33333333-3333-4333-8333-333333333333"
	deletion := VaultMutation{
		MutationID:   deletionID,
		BaseRevision: 1,
		Item: OpaqueItem{
			ItemID:            itemID,
			SchemaVersion:     1,
			Revision:          2,
			RevisionID:        deletionID,
			ParentRevisionIDs: []string{rootID},
			Deleted:           true,
			Envelope:          []byte("encrypted-trash"),
		},
	}
	result := syncOpaqueItems(
		t, testServer, token, rootResult.Cursor, []VaultMutation{deletion})
	if len(result.Changes) != 1 ||
		!result.Changes[0].Deleted ||
		string(result.Changes[0].Envelope) != "encrypted-trash" {
		t.Fatalf("encrypted trash revision: %+v", result.Changes)
	}
}

func TestSyncAcceptsPermanentTechnicalTombstone(t *testing.T) {
	authStore := &memoryBootstrapStore{}
	auth := newTestAuthService(t, authStore)
	itemStore := &memoryItemStore{}
	items := NewItemService(itemStore, auth)
	handler := NewHandler("test", stubSchema{version: 1}, nil, auth, items)
	testServer := httptest.NewServer(handler)
	defer testServer.Close()

	password := []byte("TermKeep#2026")
	mustBootstrap(t, testServer, "admin@example.com", password)
	token := mustLogin(t, testServer, "admin@example.com", password)
	itemID := "11111111-1111-4111-8111-111111111111"
	rootID := "22222222-2222-4222-8222-222222222222"
	deletionID := "33333333-3333-4333-8333-333333333333"
	root := VaultMutation{
		MutationID:   rootID,
		BaseRevision: 0,
		Item: OpaqueItem{
			ItemID:        itemID,
			SchemaVersion: 1,
			Revision:      1,
			RevisionID:    rootID,
			Envelope:      []byte("encrypted-root"),
		},
	}
	rootResult := syncOpaqueItems(
		t, testServer, token, "", []VaultMutation{root})
	deletion := VaultMutation{
		MutationID:   deletionID,
		BaseRevision: 1,
		Item: OpaqueItem{
			ItemID:            itemID,
			SchemaVersion:     1,
			Revision:          2,
			RevisionID:        deletionID,
			ParentRevisionIDs: []string{rootID},
			Deleted:           true,
			Envelope:          []byte("encrypted-trash"),
		},
	}
	deletedResult := syncOpaqueItems(
		t, testServer, token, rootResult.Cursor, []VaultMutation{deletion})
	tombstoneID := "44444444-4444-4444-8444-444444444444"
	tombstone := VaultMutation{
		MutationID:   tombstoneID,
		BaseRevision: 2,
		Item: OpaqueItem{
			ItemID:            itemID,
			SchemaVersion:     1,
			Revision:          3,
			RevisionID:        tombstoneID,
			ParentRevisionIDs: []string{deletionID},
			Deleted:           true,
			Purged:            true,
		},
	}
	result := syncOpaqueItems(
		t, testServer, token, deletedResult.Cursor, []VaultMutation{tombstone})
	if len(result.Changes) != 1 ||
		!result.Changes[0].Deleted ||
		!result.Changes[0].Purged ||
		len(result.Changes[0].Envelope) != 0 {
		t.Fatalf("technical Tombstone: %+v", result.Changes)
	}
	retry := syncOpaqueItems(
		t, testServer, token, result.Cursor, []VaultMutation{tombstone})
	if len(retry.AppliedMutationIDs) != 1 ||
		retry.AppliedMutationIDs[0] != tombstoneID ||
		len(retry.Changes) != 0 {
		t.Fatalf("Tombstone retry: %+v", retry)
	}
}

func TestSyncResultSerializesFullSnapshot(t *testing.T) {
	encoded, err := json.Marshal(SyncResult{FullSnapshot: true})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encoded, []byte(`"full_snapshot":true`)) {
		t.Fatalf("full snapshot marker missing: %s", encoded)
	}
}

func TestSyncRetryDoesNotDuplicateRevision(t *testing.T) {
	authStore := &memoryBootstrapStore{}
	auth := newTestAuthService(t, authStore)
	itemStore := &memoryItemStore{}
	items := NewItemService(itemStore, auth)
	handler := NewHandler("test", stubSchema{version: 1}, nil, auth, items)
	server := httptest.NewServer(handler)
	defer server.Close()

	password := []byte("TermKeep#2026")
	mustBootstrap(t, server, "admin@example.com", password)
	token := mustLogin(t, server, "admin@example.com", password)
	mutation := VaultMutation{
		MutationID:   "22222222-2222-4222-8222-222222222222",
		BaseRevision: 0,
		Item: OpaqueItem{
			ItemID:        "11111111-1111-4111-8111-111111111111",
			SchemaVersion: 1,
			Revision:      1,
			Envelope:      []byte("encrypted"),
		},
	}
	first := syncOpaqueItems(
		t, server, token, "", []VaultMutation{mutation})
	retry := syncOpaqueItems(
		t, server, token, first.Cursor, []VaultMutation{mutation})

	if len(retry.AppliedMutationIDs) != 1 ||
		retry.AppliedMutationIDs[0] != mutation.MutationID {
		t.Fatalf("retry did not acknowledge mutation: %+v", retry)
	}
	if len(retry.Changes) != 0 {
		t.Fatalf("retry duplicated changes: %+v", retry.Changes)
	}
	stored := itemStore.items[authStore.account.AccountID][mutation.Item.ItemID]
	if stored.Revision != 1 {
		t.Fatalf("retry advanced revision to %d", stored.Revision)
	}
}

func TestSyncRejectsMutationIDReusedWithDifferentContent(t *testing.T) {
	authStore := &memoryBootstrapStore{}
	auth := newTestAuthService(t, authStore)
	itemStore := &memoryItemStore{}
	items := NewItemService(itemStore, auth)
	handler := NewHandler("test", stubSchema{version: 1}, nil, auth, items)
	server := httptest.NewServer(handler)
	defer server.Close()

	password := []byte("TermKeep#2026")
	mustBootstrap(t, server, "admin@example.com", password)
	token := mustLogin(t, server, "admin@example.com", password)
	mutation := VaultMutation{
		MutationID:   "22222222-2222-4222-8222-222222222222",
		BaseRevision: 0,
		Item: OpaqueItem{
			ItemID:        "11111111-1111-4111-8111-111111111111",
			SchemaVersion: 1,
			Revision:      1,
			Envelope:      []byte("encrypted"),
		},
	}
	first := syncOpaqueItems(
		t, server, token, "", []VaultMutation{mutation})
	mutation.Item.Envelope = []byte("different")
	response := postSync(
		t, server, token, first.Cursor, []VaultMutation{mutation})
	response.Body.Close()

	if response.StatusCode != http.StatusConflict {
		t.Fatalf(
			"reused mutation ID status: want 409, got %d",
			response.StatusCode,
		)
	}
	stored := itemStore.items[authStore.account.AccountID][mutation.Item.ItemID]
	if !bytes.Equal(stored.Envelope, []byte("encrypted")) {
		t.Fatalf("reused mutation ID changed stored item: %q", stored.Envelope)
	}
}

func TestSyncFailureIsAuditedWithoutSemanticContent(t *testing.T) {
	authStore := &memoryBootstrapStore{}
	auth := newTestAuthService(t, authStore)
	itemStore := &memoryItemStore{}
	auditStore := &memoryAuditStore{}
	audit := NewAuditLog(auditStore, defaultAuditRetention)
	items := NewItemService(itemStore, auth, audit)
	activity := NewActivityService(audit, auth)
	handler := NewHandler(
		"test", stubSchema{version: 1}, nil, auth, items, activity)
	server := httptest.NewServer(handler)
	defer server.Close()

	password := []byte("TermKeep#2026")
	mustBootstrap(t, server, "admin@example.com", password)
	token := mustLogin(t, server, "admin@example.com", password)
	first := VaultMutation{
		MutationID:   "22222222-2222-4222-8222-222222222222",
		BaseRevision: 0,
		Item: OpaqueItem{
			ItemID:        "11111111-1111-4111-8111-111111111111",
			SchemaVersion: 1,
			Revision:      1,
			Envelope:      []byte("Semantic-Envelope-Sentinel"),
		},
	}
	syncOpaqueItems(t, server, token, "", []VaultMutation{first})
	conflict := first
	conflict.MutationID = "33333333-3333-4333-8333-333333333333"
	conflict.Item.Envelope = []byte("Different-Semantic-Sentinel")
	response := postSync(
		t, server, token, "1", []VaultMutation{conflict})
	response.Body.Close()
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("conflict status: want 409, got %d", response.StatusCode)
	}

	activityResponse := getJSONWithAuth(
		t, server.URL+"/api/v1/activity", token)
	if activityResponse.StatusCode != http.StatusOK {
		activityResponse.Body.Close()
		t.Fatalf(
			"activity status: want 200, got %d",
			activityResponse.StatusCode,
		)
	}
	var body struct {
		Events []AuditEvent `json:"events"`
	}
	decodeJSON(t, activityResponse, &body)
	if len(body.Events) != 1 ||
		body.Events[0].Type != "sync.failed" ||
		body.Events[0].AccountID != authStore.account.AccountID {
		t.Fatalf("sync failure audit: %+v", body.Events)
	}
	encoded, err := json.Marshal(body.Events)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		first.Item.ItemID,
		string(first.Item.Envelope),
		string(conflict.Item.Envelope),
	} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("sync audit contains semantic/Item field %q", forbidden)
		}
	}
}

func syncOpaqueItems(
	t *testing.T,
	server *httptest.Server,
	token string,
	cursor string,
	mutations []VaultMutation,
) SyncResult {
	t.Helper()
	response := postSync(t, server, token, cursor, mutations)
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		t.Fatalf("sync status: want 200, got %d", response.StatusCode)
	}
	var body SyncResult
	decodeJSON(t, response, &body)
	return body
}

func postSync(
	t *testing.T,
	server *httptest.Server,
	token string,
	cursor string,
	mutations []VaultMutation,
) *http.Response {
	t.Helper()
	requestBody, err := json.Marshal(syncRequest{
		Cursor:    cursor,
		Mutations: mutations,
	})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(
		http.MethodPost,
		server.URL+"/api/v1/sync",
		bytes.NewReader(requestBody),
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func putOpaqueItem(
	t *testing.T,
	server *httptest.Server,
	token string,
	itemID string,
	revision uint64,
	envelope []byte,
) *http.Response {
	t.Helper()
	requestBody, err := json.Marshal(map[string]any{
		"schema_version": 1,
		"revision":       revision,
		"envelope":       envelope,
	})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(
		http.MethodPut,
		server.URL+"/api/v1/items/"+itemID,
		bytes.NewReader(requestBody),
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

type memoryItemStore struct {
	items     map[string]map[string]OpaqueItem
	mutations map[string]map[string][32]byte
	changes   map[string][]OpaqueItem
	revisions map[string]map[string]map[string]OpaqueItem
}

func (s *memoryItemStore) PutItem(_ context.Context, accountID string, item OpaqueItem) error {
	if s.items == nil {
		s.items = make(map[string]map[string]OpaqueItem)
	}
	if s.items[accountID] == nil {
		s.items[accountID] = make(map[string]OpaqueItem)
	}
	current, exists := s.items[accountID][item.ItemID]
	if (!exists && item.Revision != 1) ||
		(exists && item.Revision != current.Revision+1) {
		return ErrItemRevisionConflict
	}
	s.items[accountID][item.ItemID] = item
	return nil
}

func (s *memoryItemStore) ListItems(_ context.Context, accountID string) ([]OpaqueItem, error) {
	var items []OpaqueItem
	for _, item := range s.items[accountID] {
		items = append(items, item)
	}
	return items, nil
}

func (s *memoryItemStore) Sync(
	ctx context.Context,
	accountID string,
	cursor string,
	mutations []VaultMutation,
) (SyncResult, error) {
	if s.mutations == nil {
		s.mutations = make(map[string]map[string][32]byte)
	}
	if s.mutations[accountID] == nil {
		s.mutations[accountID] = make(map[string][32]byte)
	}
	if s.changes == nil {
		s.changes = make(map[string][]OpaqueItem)
	}
	if s.revisions == nil {
		s.revisions = make(
			map[string]map[string]map[string]OpaqueItem)
	}
	if s.revisions[accountID] == nil {
		s.revisions[accountID] =
			make(map[string]map[string]OpaqueItem)
	}
	result := SyncResult{}
	for _, mutation := range mutations {
		digest := vaultMutationDigest(mutation)
		if stored, exists := s.mutations[accountID][mutation.MutationID]; exists {
			if stored != digest {
				return SyncResult{}, ErrMutationIDReuse
			}
			result.AppliedMutationIDs = append(
				result.AppliedMutationIDs, mutation.MutationID)
			continue
		}
		itemRevisions := s.revisions[accountID][mutation.Item.ItemID]
		if itemRevisions == nil {
			itemRevisions = make(map[string]OpaqueItem)
			s.revisions[accountID][mutation.Item.ItemID] = itemRevisions
		}
		if mutation.BaseRevision == 0 && len(itemRevisions) != 0 {
			return SyncResult{}, ErrItemRevisionConflict
		}
		var maxParentRevision uint64
		for _, parentID := range mutation.Item.ParentRevisionIDs {
			parent, exists := itemRevisions[parentID]
			if !exists {
				return SyncResult{}, ErrItemRevisionConflict
			}
			maxParentRevision = max(maxParentRevision, parent.Revision)
		}
		if mutation.BaseRevision > 0 &&
			(len(mutation.Item.ParentRevisionIDs) == 0 ||
				maxParentRevision != mutation.BaseRevision) {
			return SyncResult{}, ErrItemRevisionConflict
		}
		if _, exists := itemRevisions[mutation.Item.RevisionID]; exists {
			return SyncResult{}, ErrMutationIDReuse
		}
		itemRevisions[mutation.Item.RevisionID] = mutation.Item
		if s.items == nil {
			s.items = make(map[string]map[string]OpaqueItem)
		}
		if s.items[accountID] == nil {
			s.items[accountID] = make(map[string]OpaqueItem)
		}
		current, exists := s.items[accountID][mutation.Item.ItemID]
		if !exists || containsRevisionID(
			mutation.Item.ParentRevisionIDs, current.RevisionID) {
			s.items[accountID][mutation.Item.ItemID] = mutation.Item
		}
		if err := ctx.Err(); err != nil {
			return SyncResult{}, err
		}
		s.mutations[accountID][mutation.MutationID] = digest
		s.changes[accountID] = append(s.changes[accountID], mutation.Item)
		result.AppliedMutationIDs = append(
			result.AppliedMutationIDs, mutation.MutationID)
	}
	start := 0
	if cursor != "" {
		if _, err := fmt.Sscanf(cursor, "%d", &start); err != nil {
			return SyncResult{}, err
		}
	}
	result.Changes = append(result.Changes, s.changes[accountID][start:]...)
	result.Cursor = fmt.Sprintf("%d", len(s.changes[accountID]))
	return result, nil
}

func containsRevisionID(ids []string, target string) bool {
	for _, id := range ids {
		if id == target {
			return true
		}
	}
	return false
}
