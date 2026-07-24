package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"
)

// ErrInviteNotFound reports an unknown invitation identifier.
var ErrInviteNotFound = errors.New("invite not found")

// ErrInvalidInvite reports a token that is unknown, expired, revoked,
// consumed, or bound to another email.
var ErrInvalidInvite = errors.New("invalid invite")

// StoredInvite is the server-visible invitation record. It carries only the
// token hash and lifecycle metadata — never the plaintext token and never
// any vault material.
type StoredInvite struct {
	InviteID   string
	Email      string
	TokenHash  []byte
	CreatedBy  string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	ConsumedBy string
	ConsumedAt time.Time
	RevokedAt  time.Time
}

// Status classifies the invitation for administrative listing.
func (i StoredInvite) Status(now time.Time) string {
	switch {
	case !i.RevokedAt.IsZero():
		return "revoked"
	case i.ConsumedBy != "":
		return "consumed"
	case now.After(i.ExpiresAt):
		return "expired"
	default:
		return "active"
	}
}

// InviteStore persists invitations. Implementations must never see the
// plaintext token, only its hash.
type InviteStore interface {
	CreateInvite(ctx context.Context, invite StoredInvite) error
	ListInvites(ctx context.Context) ([]StoredInvite, error)
	RevokeInvite(ctx context.Context, inviteID string) error
}

// InviteService exposes the administrator-only invitation endpoints.
type InviteService struct {
	store InviteStore
	auth  *AuthService
}

// NewInviteService wires invitation persistence to the administrator
// authentication provided by the auth service.
func NewInviteService(store InviteStore, auth *AuthService) *InviteService {
	return &InviteService{store: store, auth: auth}
}

func (s *InviteService) register(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/invites", s.createInvite)
	mux.HandleFunc("GET /api/v1/invites", s.listInvites)
	mux.HandleFunc("POST /api/v1/invites/{id}/revoke", s.revokeInvite)
}

type createInviteRequest struct {
	Email string `json:"email"`
}

type createInviteResponse struct {
	InviteID  string    `json:"invite_id"`
	Token     string    `json:"token"`
	Email     string    `json:"email"`
	ExpiresAt time.Time `json:"expires_at"`
}

type inviteJSON struct {
	InviteID   string     `json:"invite_id"`
	Email      string     `json:"email"`
	CreatedBy  string     `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	ConsumedBy string     `json:"consumed_by,omitempty"`
	ConsumedAt *time.Time `json:"consumed_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	Status     string     `json:"status"`
}

type listInvitesResponse struct {
	Invites []inviteJSON `json:"invites"`
}

func (s *InviteService) authenticateAdmin(r *http.Request) (StoredAccessToken, error) {
	tokenStr := bearerToken(r)
	if tokenStr == "" {
		return StoredAccessToken{}, errInvalidAccessToken
	}
	token, err := s.auth.AuthenticateToken(r.Context(), tokenStr)
	if err != nil {
		return StoredAccessToken{}, err
	}
	if !token.Administrator {
		return StoredAccessToken{}, errors.New("administrator required")
	}
	return token, nil
}

func bearerToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}
	return ""
}

func (s *InviteService) createInvite(w http.ResponseWriter, r *http.Request) {
	token, err := s.authenticateAdmin(r)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req createInviteRequest
	if !decodeRequest(w, r, &req) {
		return
	}
	email, err := canonicalEmail(req.Email)
	if err != nil {
		http.Error(w, "invalid invite request", http.StatusBadRequest)
		return
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		http.Error(w, "invite creation failed", http.StatusInternalServerError)
		return
	}
	tokenStr := base64.RawURLEncoding.EncodeToString(raw)
	tokenHash := sha256.Sum256([]byte(tokenStr))

	inviteID, err := newAccountID()
	if err != nil {
		http.Error(w, "invite creation failed", http.StatusInternalServerError)
		return
	}

	now := time.Now()
	expiresAt := now.Add(48 * time.Hour)

	invite := StoredInvite{
		InviteID:  inviteID,
		Email:     email,
		TokenHash: tokenHash[:],
		CreatedBy: token.AccountID,
		CreatedAt: now,
		ExpiresAt: expiresAt,
	}

	if err := s.store.CreateInvite(r.Context(), invite); err != nil {
		http.Error(w, "invite creation failed", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusCreated, createInviteResponse{
		InviteID:  invite.InviteID,
		Token:     tokenStr,
		Email:     invite.Email,
		ExpiresAt: invite.ExpiresAt,
	})
}

func (s *InviteService) listInvites(w http.ResponseWriter, r *http.Request) {
	_, err := s.authenticateAdmin(r)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	invites, err := s.store.ListInvites(r.Context())
	if err != nil {
		http.Error(w, "failed to list invites", http.StatusInternalServerError)
		return
	}
	now := time.Now()
	out := make([]inviteJSON, 0, len(invites))
	for _, inv := range invites {
		item := inviteJSON{
			InviteID:  inv.InviteID,
			Email:     inv.Email,
			CreatedBy: inv.CreatedBy,
			CreatedAt: inv.CreatedAt,
			ExpiresAt: inv.ExpiresAt,
			Status:    inv.Status(now),
		}
		if inv.ConsumedBy != "" {
			item.ConsumedBy = inv.ConsumedBy
			item.ConsumedAt = &inv.ConsumedAt
		}
		if !inv.RevokedAt.IsZero() {
			item.RevokedAt = &inv.RevokedAt
		}
		out = append(out, item)
	}
	writeJSON(w, http.StatusOK, listInvitesResponse{Invites: out})
}

func (s *InviteService) revokeInvite(w http.ResponseWriter, r *http.Request) {
	_, err := s.authenticateAdmin(r)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	inviteID := r.PathValue("id")
	if inviteID == "" {
		http.Error(w, "invite ID required", http.StatusBadRequest)
		return
	}
	if err := s.store.RevokeInvite(r.Context(), inviteID); err != nil {
		if errors.Is(err, ErrInviteNotFound) {
			http.Error(w, "invite not found", http.StatusNotFound)
			return
		}
		http.Error(w, "failed to revoke invite", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
