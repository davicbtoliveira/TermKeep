package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAdministratorListsAccountsWithoutVaultMetadata(t *testing.T) {
	store := &memoryBootstrapStore{}
	auth := newTestAuthService(t, store)
	h := NewHandler(
		"test",
		stubSchema{version: 1},
		nil,
		auth,
		NewInviteService(store, auth),
		NewAccountService(store, auth),
	)
	srv := httptest.NewServer(h)
	defer srv.Close()

	adminPassword := []byte("TermKeep#2026")
	mustBootstrap(t, srv, "admin@example.com", adminPassword)
	adminToken := mustLogin(t, srv, "admin@example.com", adminPassword)
	invite := mustCreateInvite(t, srv, adminToken, "friend@example.com")
	mustRegister(t, srv, "friend@example.com", []byte("Friend#Pass2026"), invite.Token)

	response := getJSONWithAuth(t, srv.URL+"/api/v1/accounts", adminToken)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("list accounts status: want 200, got %d", response.StatusCode)
	}
	var body struct {
		Accounts []map[string]any `json:"accounts"`
	}
	decodeJSON(t, response, &body)
	if len(body.Accounts) != 2 {
		t.Fatalf("listed accounts: want 2, got %d", len(body.Accounts))
	}
	for _, account := range body.Accounts {
		if len(account) != 3 {
			t.Fatalf("account listing exposed unexpected fields: %#v", account)
		}
		for _, field := range []string{"uuid", "email", "status"} {
			if account[field] == nil || account[field] == "" {
				t.Fatalf("account listing missing %s: %#v", field, account)
			}
		}
	}
}

func TestNonAdministratorCannotListAccounts(t *testing.T) {
	store := &memoryBootstrapStore{}
	auth := newTestAuthService(t, store)
	h := NewHandler(
		"test",
		stubSchema{version: 1},
		nil,
		auth,
		NewInviteService(store, auth),
		NewAccountService(store, auth),
	)
	srv := httptest.NewServer(h)
	defer srv.Close()

	adminPassword := []byte("TermKeep#2026")
	mustBootstrap(t, srv, "admin@example.com", adminPassword)
	adminToken := mustLogin(t, srv, "admin@example.com", adminPassword)
	invite := mustCreateInvite(t, srv, adminToken, "friend@example.com")
	userPassword := []byte("Friend#Pass2026")
	mustRegister(t, srv, "friend@example.com", userPassword, invite.Token)
	userToken := mustLogin(t, srv, "friend@example.com", userPassword)

	response := getJSONWithAuth(t, srv.URL+"/api/v1/accounts", userToken)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("non-administrator list status: want 401, got %d", response.StatusCode)
	}
	response.Body.Close()
}
