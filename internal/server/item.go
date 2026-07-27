package server

import (
	"context"
	"errors"
	"net/http"
)

const maximumItemEnvelopeSize = 1 << 20
const maximumItemRevision = uint64(1<<63 - 1)

var ErrItemRevisionConflict = errors.New("item revision conflict")

type OpaqueItem struct {
	ItemID        string `json:"item_id"`
	SchemaVersion int    `json:"schema_version"`
	Revision      uint64 `json:"revision"`
	Envelope      []byte `json:"envelope"`
}

type ItemStore interface {
	PutItem(ctx context.Context, accountID string, item OpaqueItem) error
	ListItems(ctx context.Context, accountID string) ([]OpaqueItem, error)
}

type ItemService struct {
	store ItemStore
	auth  *AuthService
}

func NewItemService(store ItemStore, auth *AuthService) *ItemService {
	return &ItemService{store: store, auth: auth}
}

func (s *ItemService) register(mux *http.ServeMux) {
	mux.HandleFunc("PUT /api/v1/items/{id}", s.put)
	mux.HandleFunc("GET /api/v1/items", s.list)
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
