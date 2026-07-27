package server

import (
	"bytes"
	"context"
	"encoding/json"
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
	items map[string]map[string]OpaqueItem
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
