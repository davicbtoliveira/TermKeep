package server

import (
	"context"
	"errors"
	"net/http"
	"time"
)

var ErrSessionNotFound = errors.New("session not found")

type SessionStore interface {
	ListSessions(ctx context.Context, accountID string) ([]StoredAccessToken, error)
	RevokeSession(ctx context.Context, accountID, sessionID string, now time.Time) error
}

type SessionService struct {
	store SessionStore
	auth  *AuthService
}

type OnlineSession struct {
	SessionID string    `json:"session_id"`
	Host      string    `json:"host"`
	SourceIP  string    `json:"source_ip"`
	CreatedAt time.Time `json:"created_at"`
	LastUsed  time.Time `json:"last_used_at"`
	Current   bool      `json:"current"`
}

func NewSessionService(store SessionStore, auth *AuthService) *SessionService {
	return &SessionService{store: store, auth: auth}
}

func (s *SessionService) register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/sessions", s.list)
	mux.HandleFunc("DELETE /api/v1/sessions/{id}", s.revoke)
}

func (s *SessionService) revoke(w http.ResponseWriter, r *http.Request) {
	current, err := s.auth.AuthenticateToken(r.Context(), bearerToken(r))
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	sessionID := r.PathValue("id")
	if sessionID == "current" {
		sessionID = current.SessionID
	}
	if err := s.store.RevokeSession(r.Context(), current.AccountID, sessionID, time.Now()); err != nil {
		if errors.Is(err, ErrSessionNotFound) {
			http.Error(w, "session not found", http.StatusNotFound)
			return
		}
		http.Error(w, "failed to revoke session", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *SessionService) list(w http.ResponseWriter, r *http.Request) {
	current, err := s.auth.AuthenticateToken(r.Context(), bearerToken(r))
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	stored, err := s.store.ListSessions(r.Context(), current.AccountID)
	if err != nil {
		http.Error(w, "failed to list sessions", http.StatusInternalServerError)
		return
	}
	sessions := make([]OnlineSession, 0, len(stored))
	for _, item := range stored {
		sessions = append(sessions, OnlineSession{
			SessionID: item.SessionID,
			Host:      item.Host,
			SourceIP:  item.SourceIP,
			CreatedAt: item.CreatedAt,
			LastUsed:  item.LastUsedAt,
			Current:   item.SessionID == current.SessionID,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": sessions})
}
