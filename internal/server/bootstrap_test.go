package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bytemare/opaque"
)

func TestBootstrapRegistersExactlyOneAdministrator(t *testing.T) {
	store := &memoryBootstrapStore{}
	h := NewHandler("test", stubSchema{version: 1}, nil, newTestAuthService(t, store))
	srv := httptest.NewServer(h)
	defer srv.Close()

	const email = "admin@example.com"
	password := []byte("TermKeep#2026")
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
		t.Fatalf("start status: want 200, got %d", start.StatusCode)
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

	finish := postJSON(t, srv.URL+"/api/v1/bootstrap/finish", map[string]string{
		"account_id":              startBody.AccountID,
		"email":                   email,
		"registration_record":     base64.RawStdEncoding.EncodeToString(record.Serialize()),
		"password_vault_envelope": base64.RawStdEncoding.EncodeToString([]byte("encrypted-password-envelope")),
		"recovery_vault_envelope": base64.RawStdEncoding.EncodeToString([]byte("encrypted-recovery-envelope")),
	})
	if finish.StatusCode != http.StatusCreated {
		t.Fatalf("finish status: want 201, got %d", finish.StatusCode)
	}
	if store.account == nil || !store.account.Administrator {
		t.Fatal("first account was not persisted as administrator")
	}
	if bytes.Contains(store.account.OpaqueRecord, password) {
		t.Fatal("persisted OPAQUE record contains master password")
	}

	retry := postJSON(t, srv.URL+"/api/v1/bootstrap/start", map[string]string{
		"email":                "another@example.com",
		"registration_request": base64.RawStdEncoding.EncodeToString(request.Serialize()),
	})
	if retry.StatusCode != http.StatusConflict {
		t.Fatalf("second bootstrap: want 409, got %d", retry.StatusCode)
	}

	loginClient, err := opaque.NewClient(nil)
	if err != nil {
		t.Fatal(err)
	}
	ke1, err := loginClient.GenerateKE1(password)
	if err != nil {
		t.Fatal(err)
	}
	loginStart := postJSON(t, srv.URL+"/api/v1/login/start", map[string]string{
		"email": email,
		"ke1":   base64.RawStdEncoding.EncodeToString(ke1.Serialize()),
	})
	if loginStart.StatusCode != http.StatusOK {
		t.Fatalf("login start status: want 200, got %d", loginStart.StatusCode)
	}
	var loginStartBody struct {
		LoginID string `json:"login_id"`
		KE2     string `json:"ke2"`
	}
	decodeJSON(t, loginStart, &loginStartBody)
	ke2Bytes, err := base64.RawStdEncoding.DecodeString(loginStartBody.KE2)
	if err != nil {
		t.Fatal(err)
	}
	ke2, err := loginClient.Deserialize.KE2(ke2Bytes)
	if err != nil {
		t.Fatal(err)
	}
	ke3, _, _, err := loginClient.GenerateKE3(ke2, []byte(email), nil)
	if err != nil {
		t.Fatal(err)
	}
	loginFinish := postJSON(t, srv.URL+"/api/v1/login/finish", map[string]string{
		"login_id": loginStartBody.LoginID,
		"ke3":      base64.RawStdEncoding.EncodeToString(ke3.Serialize()),
	})
	if loginFinish.StatusCode != http.StatusOK {
		t.Fatalf("login finish status: want 200, got %d", loginFinish.StatusCode)
	}
	var loginFinishBody struct {
		PasswordVaultEnvelope string `json:"password_vault_envelope"`
		RecoveryVaultEnvelope string `json:"recovery_vault_envelope"`
	}
	decodeJSON(t, loginFinish, &loginFinishBody)
	if loginFinishBody.PasswordVaultEnvelope != base64.RawStdEncoding.EncodeToString(store.account.PasswordVaultEnvelope) {
		t.Fatal("authenticated login did not return password vault envelope")
	}
}

type memoryBootstrapStore struct {
	account      *BootstrapAccount
	accounts     map[string]*BootstrapAccount
	invites      []StoredInvite
	accessTokens map[string]StoredAccessToken
}

func (s *memoryBootstrapStore) InstanceEmpty(context.Context) (bool, error) {
	return s.account == nil, nil
}

func (s *memoryBootstrapStore) CreateBootstrap(_ context.Context, account BootstrapAccount) error {
	if s.account != nil {
		return ErrBootstrapClosed
	}
	s.account = &account
	s.accounts = map[string]*BootstrapAccount{account.Email: &account}
	return nil
}

func (s *memoryBootstrapStore) FindAccount(_ context.Context, email string) (StoredAccount, error) {
	account, ok := s.accounts[email]
	if !ok {
		return StoredAccount{}, ErrAccountNotFound
	}
	return StoredAccount{
		AccountID:             account.AccountID,
		Email:                 account.Email,
		Administrator:         account.Administrator,
		OpaqueRecord:          account.OpaqueRecord,
		PasswordVaultEnvelope: account.PasswordVaultEnvelope,
		RecoveryVaultEnvelope: account.RecoveryVaultEnvelope,
	}, nil
}

func (s *memoryBootstrapStore) CreateAccessToken(_ context.Context, token StoredAccessToken) error {
	if s.accessTokens == nil {
		s.accessTokens = make(map[string]StoredAccessToken)
	}
	s.accessTokens[string(token.TokenHash)] = token
	return nil
}

func (s *memoryBootstrapStore) FindAccessToken(_ context.Context, tokenHash []byte) (StoredAccessToken, error) {
	if token, ok := s.accessTokens[string(tokenHash)]; ok {
		return token, nil
	}
	return StoredAccessToken{}, ErrAccessTokenNotFound
}

func (s *memoryBootstrapStore) CreateInvite(_ context.Context, invite StoredInvite) error {
	s.invites = append(s.invites, invite)
	return nil
}

func (s *memoryBootstrapStore) ListInvites(context.Context) ([]StoredInvite, error) {
	return s.invites, nil
}

func (s *memoryBootstrapStore) RevokeInvite(_ context.Context, inviteID string) error {
	for i := range s.invites {
		if s.invites[i].InviteID == inviteID {
			s.invites[i].RevokedAt = time.Now()
			return nil
		}
	}
	return ErrInviteNotFound
}

func (s *memoryBootstrapStore) ValidateInvite(_ context.Context, tokenHash []byte, email string, now time.Time) error {
	for _, invite := range s.invites {
		if bytes.Equal(invite.TokenHash, tokenHash) &&
			invite.Email == email &&
			invite.ConsumedBy == "" &&
			invite.RevokedAt.IsZero() &&
			now.Before(invite.ExpiresAt) {
			return nil
		}
	}
	return ErrInvalidInvite
}

func (s *memoryBootstrapStore) CreateInvitedAccount(_ context.Context, tokenHash []byte, account BootstrapAccount, now time.Time) error {
	if err := s.ValidateInvite(context.Background(), tokenHash, account.Email, now); err != nil {
		return err
	}
	if _, exists := s.accounts[account.Email]; exists {
		return errors.New("account already exists")
	}
	s.accounts[account.Email] = &account
	for i := range s.invites {
		if bytes.Equal(s.invites[i].TokenHash, tokenHash) {
			s.invites[i].ConsumedBy = account.AccountID
			s.invites[i].ConsumedAt = now
			return nil
		}
	}
	return ErrInvalidInvite
}

func newTestAuthService(t *testing.T, store AuthStore) *AuthService {
	t.Helper()
	configuration := opaque.DefaultConfiguration()
	opaqueServer, err := opaque.NewServer(configuration)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, publicKey := configuration.KeyGen()
	if err := opaqueServer.SetKeyMaterial(&opaque.ServerKeyMaterial{
		PrivateKey:     privateKey,
		PublicKeyBytes: publicKey.Encode(),
		OPRFGlobalSeed: configuration.GenerateOPRFSeed(),
	}); err != nil {
		t.Fatal(err)
	}
	return NewAuthService(opaqueServer, store)
}

func postJSON(t *testing.T, url string, body any) *http.Response {
	t.Helper()
	return postJSONWithAuth(t, url, body, "")
}

// postJSONWithAuth posts a JSON body, attaching a bearer token when given.
func postJSONWithAuth(t *testing.T, url string, body any, accessToken string) *http.Response {
	t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	if accessToken != "" {
		request.Header.Set("Authorization", "Bearer "+accessToken)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func decodeJSON(t *testing.T, response *http.Response, out any) {
	t.Helper()
	defer response.Body.Close()
	if err := json.NewDecoder(response.Body).Decode(out); err != nil {
		t.Fatal(err)
	}
}
