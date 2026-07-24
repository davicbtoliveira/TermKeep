package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/bytemare/opaque"
)

func TestInvitedUserRegistersAndLogsIn(t *testing.T) {
	store := &memoryBootstrapStore{}
	auth := newTestAuthService(t, store)
	h := NewHandler("test", stubSchema{version: 1}, nil, auth, NewInviteService(store, auth))
	srv := httptest.NewServer(h)
	defer srv.Close()

	adminPassword := []byte("TermKeep#2026")
	mustBootstrap(t, srv, "admin@example.com", adminPassword)
	adminToken := mustLogin(t, srv, "admin@example.com", adminPassword)
	invite := mustCreateInvite(t, srv, adminToken, "friend@example.com")

	userPassword := []byte("Friend#Pass2026")
	mustRegister(t, srv, "friend@example.com", userPassword, invite.Token)
	mustLogin(t, srv, "friend@example.com", userPassword)
}

func TestInviteCannotBeReused(t *testing.T) {
	store := &memoryBootstrapStore{}
	auth := newTestAuthService(t, store)
	h := NewHandler("test", stubSchema{version: 1}, nil, auth, NewInviteService(store, auth))
	srv := httptest.NewServer(h)
	defer srv.Close()

	adminPassword := []byte("TermKeep#2026")
	mustBootstrap(t, srv, "admin@example.com", adminPassword)
	adminToken := mustLogin(t, srv, "admin@example.com", adminPassword)
	invite := mustCreateInvite(t, srv, adminToken, "friend@example.com")

	userPassword := []byte("Friend#Pass2026")
	mustRegister(t, srv, "friend@example.com", userPassword, invite.Token)

	reuse := postRegistrationStart(t, srv, "friend@example.com", userPassword, invite.Token)
	if reuse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("reuse invite status: want 401, got %d", reuse.StatusCode)
	}
	reuse.Body.Close()
}

func TestInviteCannotBeUsedWithAnotherEmail(t *testing.T) {
	store := &memoryBootstrapStore{}
	auth := newTestAuthService(t, store)
	h := NewHandler("test", stubSchema{version: 1}, nil, auth, NewInviteService(store, auth))
	srv := httptest.NewServer(h)
	defer srv.Close()

	adminPassword := []byte("TermKeep#2026")
	mustBootstrap(t, srv, "admin@example.com", adminPassword)
	adminToken := mustLogin(t, srv, "admin@example.com", adminPassword)
	invite := mustCreateInvite(t, srv, adminToken, "friend@example.com")

	response := postRegistrationStart(t, srv, "attacker@example.com", []byte("Attacker#Pass2026"), invite.Token)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("email-swapped invite status: want 401, got %d", response.StatusCode)
	}
	response.Body.Close()
}

func TestExpiredInviteCannotRegister(t *testing.T) {
	store := &memoryBootstrapStore{}
	auth := newTestAuthService(t, store)
	h := NewHandler("test", stubSchema{version: 1}, nil, auth, NewInviteService(store, auth))
	srv := httptest.NewServer(h)
	defer srv.Close()

	adminPassword := []byte("TermKeep#2026")
	mustBootstrap(t, srv, "admin@example.com", adminPassword)
	adminToken := mustLogin(t, srv, "admin@example.com", adminPassword)
	invite := mustCreateInvite(t, srv, adminToken, "friend@example.com")
	store.invites[0].ExpiresAt = time.Now().Add(-time.Minute)

	response := postRegistrationStart(t, srv, "friend@example.com", []byte("Friend#Pass2026"), invite.Token)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expired invite status: want 401, got %d", response.StatusCode)
	}
	response.Body.Close()
}

func TestRevokedInviteCannotRegister(t *testing.T) {
	store := &memoryBootstrapStore{}
	auth := newTestAuthService(t, store)
	h := NewHandler("test", stubSchema{version: 1}, nil, auth, NewInviteService(store, auth))
	srv := httptest.NewServer(h)
	defer srv.Close()

	adminPassword := []byte("TermKeep#2026")
	mustBootstrap(t, srv, "admin@example.com", adminPassword)
	adminToken := mustLogin(t, srv, "admin@example.com", adminPassword)
	invite := mustCreateInvite(t, srv, adminToken, "friend@example.com")

	revoke := postJSONWithAuth(t, srv.URL+"/api/v1/invites/"+invite.InviteID+"/revoke", nil, adminToken)
	if revoke.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke invite status: want 204, got %d", revoke.StatusCode)
	}
	revoke.Body.Close()

	response := postRegistrationStart(t, srv, "friend@example.com", []byte("Friend#Pass2026"), invite.Token)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked invite status: want 401, got %d", response.StatusCode)
	}
	response.Body.Close()
}

func TestConcurrentInviteConsumptionRegistersExactlyOneAccount(t *testing.T) {
	store := &memoryBootstrapStore{}
	auth := newTestAuthService(t, store)
	h := NewHandler("test", stubSchema{version: 1}, nil, auth, NewInviteService(store, auth))
	srv := httptest.NewServer(h)
	defer srv.Close()

	adminPassword := []byte("TermKeep#2026")
	mustBootstrap(t, srv, "admin@example.com", adminPassword)
	adminToken := mustLogin(t, srv, "admin@example.com", adminPassword)
	invite := mustCreateInvite(t, srv, adminToken, "friend@example.com")

	password := []byte("Friend#Pass2026")
	first := prepareRegistration(t, srv, "friend@example.com", password, invite.Token)
	second := prepareRegistration(t, srv, "friend@example.com", password, invite.Token)

	start := make(chan struct{})
	statuses := make(chan int, 2)
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, body := range []map[string]string{first, second} {
		wg.Add(1)
		go func(body map[string]string) {
			defer wg.Done()
			<-start
			status, err := postJSONStatus(srv.URL+"/api/v1/register/finish", body)
			if err != nil {
				errs <- err
				return
			}
			statuses <- status
		}(body)
	}
	close(start)
	wg.Wait()
	close(statuses)
	close(errs)

	for err := range errs {
		t.Error(err)
	}
	var created, rejected int
	for status := range statuses {
		switch status {
		case http.StatusCreated:
			created++
		case http.StatusUnauthorized:
			rejected++
		default:
			t.Errorf("concurrent registration returned HTTP %d", status)
		}
	}
	if created != 1 || rejected != 1 {
		t.Fatalf("concurrent results: want one 201 and one 401, got %d and %d", created, rejected)
	}
}

func TestAccountsReceiveOnlyTheirOwnVaultEnvelopes(t *testing.T) {
	store := &memoryBootstrapStore{}
	auth := newTestAuthService(t, store)
	h := NewHandler("test", stubSchema{version: 1}, nil, auth, NewInviteService(store, auth))
	srv := httptest.NewServer(h)
	defer srv.Close()

	adminPassword := []byte("TermKeep#2026")
	mustBootstrap(t, srv, "admin@example.com", adminPassword)
	adminLogin := mustLoginResponse(t, srv, "admin@example.com", adminPassword)
	invite := mustCreateInvite(t, srv, adminLogin.AccessToken, "friend@example.com")

	userPassword := []byte("Friend#Pass2026")
	mustRegister(t, srv, "friend@example.com", userPassword, invite.Token)
	userLogin := mustLoginResponse(t, srv, "friend@example.com", userPassword)

	if adminLogin.AccountID == userLogin.AccountID {
		t.Fatal("administrator and invited user received the same account UUID")
	}
	if adminLogin.PasswordVaultEnvelope == userLogin.PasswordVaultEnvelope ||
		adminLogin.RecoveryVaultEnvelope == userLogin.RecoveryVaultEnvelope {
		t.Fatal("accounts received overlapping vault envelopes")
	}
	if got := userLogin.PasswordVaultEnvelope; got != base64.RawStdEncoding.EncodeToString([]byte("friend-password-envelope")) {
		t.Fatal("invited user did not receive its own password vault envelope")
	}
	if got := adminLogin.PasswordVaultEnvelope; got != base64.RawStdEncoding.EncodeToString([]byte("encrypted-password-envelope")) {
		t.Fatal("administrator did not receive its own password vault envelope")
	}
}

type testInvite struct {
	InviteID string `json:"invite_id"`
	Token    string `json:"token"`
}

func mustCreateInvite(t *testing.T, srv *httptest.Server, adminToken, email string) testInvite {
	t.Helper()
	response := postJSONWithAuth(t, srv.URL+"/api/v1/invites", map[string]string{
		"email": email,
	}, adminToken)
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("create invite status: want 201, got %d", response.StatusCode)
	}
	var invite testInvite
	decodeJSON(t, response, &invite)
	return invite
}

func postRegistrationStart(t *testing.T, srv *httptest.Server, email string, password []byte, inviteToken string) *http.Response {
	t.Helper()
	client, err := opaque.NewClient(nil)
	if err != nil {
		t.Fatal(err)
	}
	request, err := client.RegistrationInit(password)
	if err != nil {
		t.Fatal(err)
	}
	return postJSON(t, srv.URL+"/api/v1/register/start", map[string]string{
		"email":                email,
		"invite_token":         inviteToken,
		"registration_request": base64.RawStdEncoding.EncodeToString(request.Serialize()),
	})
}

func mustRegister(t *testing.T, srv *httptest.Server, email string, password []byte, inviteToken string) {
	t.Helper()
	body := prepareRegistration(t, srv, email, password, inviteToken)
	finish := postJSON(t, srv.URL+"/api/v1/register/finish", body)
	if finish.StatusCode != http.StatusCreated {
		t.Fatalf("registration finish status: want 201, got %d", finish.StatusCode)
	}
	finish.Body.Close()
}

func prepareRegistration(t *testing.T, srv *httptest.Server, email string, password []byte, inviteToken string) map[string]string {
	t.Helper()
	client, err := opaque.NewClient(nil)
	if err != nil {
		t.Fatal(err)
	}
	request, err := client.RegistrationInit(password)
	if err != nil {
		t.Fatal(err)
	}
	start := postJSON(t, srv.URL+"/api/v1/register/start", map[string]string{
		"email":                email,
		"invite_token":         inviteToken,
		"registration_request": base64.RawStdEncoding.EncodeToString(request.Serialize()),
	})
	if start.StatusCode != http.StatusOK {
		t.Fatalf("registration start status: want 200, got %d", start.StatusCode)
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
	response, err := client.Deserialize.RegistrationResponse(responseBytes)
	if err != nil {
		t.Fatal(err)
	}
	record, _, err := client.RegistrationFinalize(response, []byte(email), nil)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]string{
		"account_id":              startBody.AccountID,
		"email":                   email,
		"invite_token":            inviteToken,
		"registration_record":     base64.RawStdEncoding.EncodeToString(record.Serialize()),
		"password_vault_envelope": base64.RawStdEncoding.EncodeToString([]byte("friend-password-envelope")),
		"recovery_vault_envelope": base64.RawStdEncoding.EncodeToString([]byte("friend-recovery-envelope")),
	}
}

func postJSONStatus(url string, body any) (int, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return 0, err
	}
	response, err := http.Post(url, "application/json", bytes.NewReader(payload))
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	return response.StatusCode, nil
}
