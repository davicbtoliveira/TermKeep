package server

import (
	"context"
	"errors"
	"net/http"
)

const maximumItemEnvelopeSize = 1 << 20
const maximumItemRevision = uint64(1<<63 - 1)
const maximumSyncMutations = 100

var ErrItemRevisionConflict = errors.New("item revision conflict")
var ErrInvalidSyncCursor = errors.New("invalid synchronization cursor")
var ErrMutationIDReuse = errors.New("mutation ID reused with different content")

type OpaqueItem struct {
	ItemID        string `json:"item_id"`
	SchemaVersion int    `json:"schema_version"`
	Revision      uint64 `json:"revision"`
	Envelope      []byte `json:"envelope"`
}

type VaultMutation struct {
	MutationID   string     `json:"mutation_id"`
	BaseRevision uint64     `json:"base_revision"`
	Item         OpaqueItem `json:"item"`
}

type SyncResult struct {
	Cursor             string       `json:"cursor"`
	AppliedMutationIDs []string     `json:"applied_mutation_ids"`
	Changes            []OpaqueItem `json:"changes"`
}

type ItemStore interface {
	PutItem(ctx context.Context, accountID string, item OpaqueItem) error
	ListItems(ctx context.Context, accountID string) ([]OpaqueItem, error)
}

type SyncStore interface {
	Sync(
		ctx context.Context,
		accountID string,
		cursor string,
		mutations []VaultMutation,
	) (SyncResult, error)
}

type ItemService struct {
	store     ItemStore
	syncStore SyncStore
	auth      *AuthService
}

func NewItemService(store ItemStore, auth *AuthService) *ItemService {
	syncStore, _ := store.(SyncStore)
	return &ItemService{store: store, syncStore: syncStore, auth: auth}
}

func (s *ItemService) register(mux *http.ServeMux) {
	mux.HandleFunc("PUT /api/v1/items/{id}", s.put)
	mux.HandleFunc("GET /api/v1/items", s.list)
	mux.HandleFunc("POST /api/v1/sync", s.sync)
}

type putItemRequest struct {
	SchemaVersion int    `json:"schema_version"`
	Revision      uint64 `json:"revision"`
	Envelope      []byte `json:"envelope"`
}

func (s *ItemService) put(w http.ResponseWriter, r *http.Request) {
	token, err := s.auth.AuthenticateToken(r.Context(), bearerToken(r))
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var request putItemRequest
	if !decodeRequest(w, r, &request) {
		return
	}
	itemID := r.PathValue("id")
	if itemID == "" || request.SchemaVersion < 1 || request.Revision < 1 ||
		request.Revision > maximumItemRevision ||
		len(request.Envelope) == 0 || len(request.Envelope) > maximumItemEnvelopeSize {
		http.Error(w, "invalid item", http.StatusBadRequest)
		return
	}
	if err := s.store.PutItem(r.Context(), token.AccountID, OpaqueItem{
		ItemID:        itemID,
		SchemaVersion: request.SchemaVersion,
		Revision:      request.Revision,
		Envelope:      request.Envelope,
	}); err != nil {
		if errors.Is(err, ErrItemRevisionConflict) {
			http.Error(w, "item revision conflict", http.StatusConflict)
			return
		}
		http.Error(w, "failed to store item", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *ItemService) list(w http.ResponseWriter, r *http.Request) {
	token, err := s.auth.AuthenticateToken(r.Context(), bearerToken(r))
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	items, err := s.store.ListItems(r.Context(), token.AccountID)
	if err != nil {
		http.Error(w, "failed to list items", http.StatusInternalServerError)
		return
	}
	if items == nil {
		items = []OpaqueItem{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

type syncRequest struct {
	Cursor    string          `json:"cursor"`
	Mutations []VaultMutation `json:"mutations"`
}

func (s *ItemService) sync(w http.ResponseWriter, r *http.Request) {
	token, err := s.auth.AuthenticateToken(r.Context(), bearerToken(r))
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var request syncRequest
	if !decodeRequest(w, r, &request) {
		return
	}
	if s.syncStore == nil || len(request.Mutations) > maximumSyncMutations ||
		!validMutations(request.Mutations) {
		http.Error(w, "invalid synchronization", http.StatusBadRequest)
		return
	}
	result, err := s.syncStore.Sync(
		r.Context(), token.AccountID, request.Cursor, request.Mutations)
	if err != nil {
		if errors.Is(err, ErrItemRevisionConflict) {
			http.Error(w, "item revision conflict", http.StatusConflict)
			return
		}
		if errors.Is(err, ErrMutationIDReuse) {
			http.Error(w, "mutation ID conflict", http.StatusConflict)
			return
		}
		if errors.Is(err, ErrInvalidSyncCursor) {
			http.Error(w, "invalid synchronization cursor", http.StatusBadRequest)
			return
		}
		http.Error(w, "synchronization failed", http.StatusInternalServerError)
		return
	}
	if result.AppliedMutationIDs == nil {
		result.AppliedMutationIDs = []string{}
	}
	if result.Changes == nil {
		result.Changes = []OpaqueItem{}
	}
	writeJSON(w, http.StatusOK, result)
}

func validMutations(mutations []VaultMutation) bool {
	for _, mutation := range mutations {
		item := mutation.Item
		if !validUUID(mutation.MutationID) || item.ItemID == "" ||
			item.SchemaVersion < 1 || item.Revision < 1 ||
			item.Revision > maximumItemRevision ||
			item.Revision != mutation.BaseRevision+1 ||
			len(item.Envelope) == 0 ||
			len(item.Envelope) > maximumItemEnvelopeSize {
			return false
		}
	}
	return true
}

func validUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index, char := range value {
		switch index {
		case 8, 13, 18, 23:
			if char != '-' {
				return false
			}
		default:
			if !((char >= '0' && char <= '9') ||
				(char >= 'a' && char <= 'f') ||
				(char >= 'A' && char <= 'F')) {
				return false
			}
		}
	}
	return true
}
