package server

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bytemare/opaque"
)

// TestAdministratorCreatesInviteAfterLogin is the tracer bullet for the
// invitation flow: a logged-in administrator creates a single-use invite
// bound to an email, and the server persists only the token hash.
func TestAdministratorCreatesInviteAfterLogin(t *testing.T) {
	store := &memoryBootstrapStore{}
	auth := newTestAuthService(t, store)
	h := NewHandler("test", stubSchema{version: 1}, nil, auth, NewInviteService(store, auth))
	srv := httptest.NewServer(h)
	defer srv.Close()

	const email = "admin@example.com"
	password := []byte("TermKeep#2026")
	mustBootstrap(t, srv, email, password)
	token := mustLogin(t, srv, email, password)

	response := postJSONWithAuth(t, srv.URL+"/api/v1/invites", map[string]any{
		"email": "friend@example.com",
	}, token)
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("create invite status: want 201, got %d", response.StatusCode)
	}
	var body struct {
		InviteID  string    `json:"invite_id"`
		Token     string    `json:"token"`
		Email     string    `json:"email"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	decodeJSON(t, response, &body)
	if body.InviteID == "" || body.Token == "" || body.Email != "friend@example.com" {
		t.Fatalf("invite response incomplete: %+v", body)
	}
	if ttl := time.Until(body.ExpiresAt); ttl < 47*time.Hour || ttl > 48*time.Hour {
		t.Fatalf("default invite TTL: want ~48h, got %s", ttl)
	}

	if len(store.invites) != 1 {
		t.Fatalf("persisted invites: want 1, got %d", len(store.invites))
	}
	stored := store.invites[0]
	if stored.Email != "friend@example.com" || stored.CreatedBy == "" {
		t.Fatalf("persisted invite missing email or creator: %+v", stored)
	}
	if len(stored.TokenHash) == 0 || strings.Contains(string(stored.TokenHash), body.Token) {
		t.Fatal("server persisted the plaintext invite token")
	}
}

// TestInviteEndpointsRejectUnauthenticated proves the administrative surface
// is closed without a valid bearer token.
func TestInviteEndpointsRejectUnauthenticated(t *testing.T) {
	store := &memoryBootstrapStore{}
	auth := newTestAuthService(t, store)
	h := NewHandler("test", stubSchema{version: 1}, nil, auth, NewInviteService(store, auth))
	srv := httptest.NewServer(h)
	defer srv.Close()

	mustBootstrap(t, srv, "admin@example.com", []byte("TermKeep#2026"))

	for _, token := range []string{"", "not-a-real-token"} {
		response := postJSONWithAuth(t, srv.URL+"/api/v1/invites", map[string]any{
			"email": "friend@example.com",
		}, token)
		if response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("create invite with token %q: want 401, got %d", token, response.StatusCode)
		}
		response.Body.Close()
	}
	if len(store.invites) != 0 {
		t.Fatal("unauthenticated request persisted an invite")
	}
}

// mustBootstrap drives the public bootstrap endpoints with a real OPAQUE
// client, exactly as the compiled CLI does.
func mustBootstrap(t *testing.T, srv *httptest.Server, email string, password []byte) {
	t.Helper()
	client, err := opaque.NewClient(nil)
	if err != nil {
		t.Fatal(err)
	}
	request, err := client.RegistrationInit(password)
	if err != nil {
		t.Fatal(err)
	}
	start := postJSON(t, srv.URL+"/api/v1/bootstrap/start", map[string]string{
		"email":                email,
		"registration_request": base64.RawStdEncoding.EncodeToString(request.Serialize()),
	})
	if start.StatusCode != http.StatusOK {
		t.Fatalf("bootstrap start status: want 200, got %d", start.StatusCode)
	}
	var startBody struct {
		AccountID            string `json:"account_id"`
		RegistrationResponse string `json:"registration_response"`
	}
	decodeJSON(t, start, &startBody)
	responseBytes, err := base64.RawStdEncoding.DecodeString(startBody.RegistrationResponse)
	if err != nil {
		t.Fatal(err)
	}
	registrationResponse, err := client.Deserialize.RegistrationResponse(responseBytes)
	if err != nil {
		t.Fatal(err)
	}
	record, _, err := client.RegistrationFinalize(registrationResponse, []byte(email), nil)
	if err != nil {
		t.Fatal(err)
	}
	finish := postJSON(t, srv.URL+"/api/v1/bootstrap/finish", map[string]string{
		"account_id":              startBody.AccountID,
		"email":                   email,
		"registration_record":     base64.RawStdEncoding.EncodeToString(record.Serialize()),
		"password_vault_envelope": base64.RawStdEncoding.EncodeToString([]byte("encrypted-password-envelope")),
		"recovery_vault_envelope": base64.RawStdEncoding.EncodeToString([]byte("encrypted-recovery-envelope")),
	})
	if finish.StatusCode != http.StatusCreated {
		t.Fatalf("bootstrap finish status: want 201, got %d", finish.StatusCode)
	}
	finish.Body.Close()
}

// mustLogin completes an OPAQUE login through the public endpoints and
// returns the short-lived access token authorizing later requests.
func mustLogin(t *testing.T, srv *httptest.Server, email string, password []byte) string {
	t.Helper()
	response := mustLoginResponse(t, srv, email, password)
	if response.AccessToken == "" {
		t.Fatal("login finish did not return an access token")
	}
	return response.AccessToken
}

func mustLoginResponse(t *testing.T, srv *httptest.Server, email string, password []byte) loginFinishResponse {
	t.Helper()
	client, err := opaque.NewClient(nil)
	if err != nil {
		t.Fatal(err)
	}
	ke1, err := client.GenerateKE1(password)
	if err != nil {
		t.Fatal(err)
	}
	start := postJSON(t, srv.URL+"/api/v1/login/start", map[string]string{
		"email": email,
		"ke1":   base64.RawStdEncoding.EncodeToString(ke1.Serialize()),
	})
	if start.StatusCode != http.StatusOK {
		t.Fatalf("login start status: want 200, got %d", start.StatusCode)
	}
	var startBody struct {
		LoginID string `json:"login_id"`
		KE2     string `json:"ke2"`
	}
	decodeJSON(t, start, &startBody)
	ke2Bytes, err := base64.RawStdEncoding.DecodeString(startBody.KE2)
	if err != nil {
		t.Fatal(err)
	}
	ke2, err := client.Deserialize.KE2(ke2Bytes)
	if err != nil {
		t.Fatal(err)
	}
	ke3, _, _, err := client.GenerateKE3(ke2, []byte(email), nil)
	if err != nil {
		t.Fatal(err)
	}
	finish := postJSON(t, srv.URL+"/api/v1/login/finish", map[string]string{
		"login_id": startBody.LoginID,
		"ke3":      base64.RawStdEncoding.EncodeToString(ke3.Serialize()),
	})
	if finish.StatusCode != http.StatusOK {
		t.Fatalf("login finish status: want 200, got %d", finish.StatusCode)
	}
	var finishBody loginFinishResponse
	decodeJSON(t, finish, &finishBody)
	return finishBody
}

func getJSONWithAuth(t *testing.T, url string, accessToken string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if accessToken != "" {
		request.Header.Set("Authorization", "Bearer "+accessToken)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func TestAdministratorListsAndRevokesInvites(t *testing.T) {
	store := &memoryBootstrapStore{}
	auth := newTestAuthService(t, store)
	h := NewHandler("test", stubSchema{version: 1}, nil, auth, NewInviteService(store, auth))
	srv := httptest.NewServer(h)
	defer srv.Close()

	const email = "admin@example.com"
	password := []byte("TermKeep#2026")
	mustBootstrap(t, srv, email, password)
	token := mustLogin(t, srv, email, password)

	resp := postJSONWithAuth(t, srv.URL+"/api/v1/invites", map[string]any{"email": "user1@example.com"}, token)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create invite: want 201, got %d", resp.StatusCode)
	}
	var created struct {
		InviteID string `json:"invite_id"`
	}
	decodeJSON(t, resp, &created)

	listResp := getJSONWithAuth(t, srv.URL+"/api/v1/invites", token)
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list invites: want 200, got %d", listResp.StatusCode)
	}
	var listBody struct {
		Invites []struct {
			InviteID string `json:"invite_id"`
			Email    string `json:"email"`
			Status   string `json:"status"`
		} `json:"invites"`
	}
	decodeJSON(t, listResp, &listBody)
	if len(listBody.Invites) != 1 || listBody.Invites[0].Email != "user1@example.com" || listBody.Invites[0].Status != "active" {
		t.Fatalf("unexpected list invites output: %+v", listBody)
	}

	revokeResp := postJSONWithAuth(t, srv.URL+"/api/v1/invites/"+created.InviteID+"/revoke", nil, token)
	if revokeResp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke invite: want 204, got %d", revokeResp.StatusCode)
	}

	listResp2 := getJSONWithAuth(t, srv.URL+"/api/v1/invites", token)
	decodeJSON(t, listResp2, &listBody)
	if len(listBody.Invites) != 1 || listBody.Invites[0].Status != "revoked" {
		t.Fatalf("expected invite status revoked: %+v", listBody)
	}
}
