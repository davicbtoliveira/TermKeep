package server

import (
	"context"
	"net/http"
)

// AccountSummary is the complete administrative view of an account. Vault
// envelopes and semantic vault metadata are deliberately absent.
type AccountSummary struct {
	AccountID string
	Email     string
	Status    string
}

// AccountStore exposes only the metadata needed by account administration.
type AccountStore interface {
	ListAccounts(ctx context.Context) ([]AccountSummary, error)
}

// AccountService exposes administrator-only account metadata.
type AccountService struct {
	store AccountStore
	auth  *AuthService
}

func NewAccountService(store AccountStore, auth *AuthService) *AccountService {
	return &AccountService{store: store, auth: auth}
}

func (s *AccountService) register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/accounts", s.listAccounts)
}

type accountJSON struct {
	AccountID string `json:"uuid"`
	Email     string `json:"email"`
	Status    string `json:"status"`
}

type listAccountsResponse struct {
	Accounts []accountJSON `json:"accounts"`
}

func (s *AccountService) listAccounts(w http.ResponseWriter, r *http.Request) {
	if _, err := authenticateAdministrator(s.auth, r); err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	accounts, err := s.store.ListAccounts(r.Context())
	if err != nil {
		http.Error(w, "failed to list accounts", http.StatusInternalServerError)
		return
	}
	out := make([]accountJSON, 0, len(accounts))
	for _, account := range accounts {
		out = append(out, accountJSON{
			AccountID: account.AccountID,
			Email:     account.Email,
			Status:    account.Status,
		})
	}
	writeJSON(w, http.StatusOK, listAccountsResponse{Accounts: out})
}
