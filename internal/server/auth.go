package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"strings"
	"sync"
	"time"

	"github.com/bytemare/opaque"
)

var ErrBootstrapClosed = errors.New("bootstrap registration is closed")
var ErrAccountNotFound = errors.New("account not found")

var errInvalidLogin = errors.New("invalid login")

// BootstrapStore persists the first account and its opaque client-created
// vault envelopes. CreateBootstrap must reject concurrent second attempts.
type BootstrapStore interface {
	InstanceEmpty(ctx context.Context) (bool, error)
	CreateBootstrap(ctx context.Context, account BootstrapAccount) error
	FindAccount(ctx context.Context, email string) (StoredAccount, error)
}

// BootstrapAccount is the only account material written during bootstrap.
// OpaqueRecord and vault envelopes must never contain plaintext secrets.
type BootstrapAccount struct {
	AccountID             string
	Email                 string
	Administrator         bool
	OpaqueRecord          []byte
	PasswordVaultEnvelope []byte
	RecoveryVaultEnvelope []byte
}

// StoredAccount is server-visible authentication and ciphertext material.
// It excludes all decrypted vault data by design.
type StoredAccount struct {
	AccountID             string
	Email                 string
	OpaqueRecord          []byte
	PasswordVaultEnvelope []byte
	RecoveryVaultEnvelope []byte
}

// AuthService implements bootstrap registration while keeping OPAQUE protocol
// details out of the HTTP handler.
type AuthService struct {
	opaque  *opaque.Server
	config  *opaque.Configuration
	store   BootstrapStore
	mu      sync.Mutex
	pending map[string]pendingLogin
}

type pendingLogin struct {
	account       *StoredAccount
	clientMAC     []byte
	sessionSecret []byte
	expiresAt     time.Time
}

// NewAuthService configures the OPAQUE server and persistence boundary used by
// registration and later authentication flows.
func NewAuthService(opaqueServer *opaque.Server, store BootstrapStore) *AuthService {
	return &AuthService{
		opaque:  opaqueServer,
		config:  opaque.DefaultConfiguration(),
		store:   store,
		pending: make(map[string]pendingLogin),
	}
}

func (a *AuthService) register(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/bootstrap/start", a.startBootstrap)
	mux.HandleFunc("POST /api/v1/bootstrap/finish", a.finishBootstrap)
	mux.HandleFunc("POST /api/v1/login/start", a.startLogin)
	mux.HandleFunc("POST /api/v1/login/finish", a.finishLogin)
}

type bootstrapStartRequest struct {
	Email               string `json:"email"`
	RegistrationRequest string `json:"registration_request"`
}

type bootstrapStartResponse struct {
	AccountID            string `json:"account_id"`
	RegistrationResponse string `json:"registration_response"`
}

type bootstrapFinishRequest struct {
	AccountID             string `json:"account_id"`
	Email                 string `json:"email"`
	RegistrationRecord    string `json:"registration_record"`
	PasswordVaultEnvelope string `json:"password_vault_envelope"`
	RecoveryVaultEnvelope string `json:"recovery_vault_envelope"`
}

func (a *AuthService) startBootstrap(w http.ResponseWriter, r *http.Request) {
	var request bootstrapStartRequest
	if !decodeRequest(w, r, &request) {
		return
	}
	email, err := canonicalEmail(request.Email)
	if err != nil {
		http.Error(w, "invalid bootstrap request", http.StatusBadRequest)
		return
	}
	encoded, err := base64.RawStdEncoding.DecodeString(request.RegistrationRequest)
	if err != nil {
		http.Error(w, "invalid bootstrap request", http.StatusBadRequest)
		return
	}
	response, err := a.start(r.Context(), email, encoded)
	if err != nil {
		writeBootstrapError(w, err)
		return
	}
	accountID, err := newAccountID()
	if err != nil {
		http.Error(w, "bootstrap unavailable", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, bootstrapStartResponse{
		AccountID:            accountID,
		RegistrationResponse: base64.RawStdEncoding.EncodeToString(response),
	})
}

func (a *AuthService) finishBootstrap(w http.ResponseWriter, r *http.Request) {
	var request bootstrapFinishRequest
	if !decodeRequest(w, r, &request) {
		return
	}
	email, err := canonicalEmail(request.Email)
	if err != nil {
		http.Error(w, "invalid bootstrap request", http.StatusBadRequest)
		return
	}
	record, err := base64.RawStdEncoding.DecodeString(request.RegistrationRecord)
	if err != nil {
		http.Error(w, "invalid bootstrap request", http.StatusBadRequest)
		return
	}
	passwordEnvelope, err := base64.RawStdEncoding.DecodeString(request.PasswordVaultEnvelope)
	if err != nil || len(passwordEnvelope) == 0 {
		http.Error(w, "invalid bootstrap request", http.StatusBadRequest)
		return
	}
	recoveryEnvelope, err := base64.RawStdEncoding.DecodeString(request.RecoveryVaultEnvelope)
	if err != nil || len(recoveryEnvelope) == 0 {
		http.Error(w, "invalid bootstrap request", http.StatusBadRequest)
		return
	}
	if err := a.finish(r.Context(), request.AccountID, email, record, passwordEnvelope, recoveryEnvelope); err != nil {
		writeBootstrapError(w, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (a *AuthService) start(ctx context.Context, email string, encodedRequest []byte) ([]byte, error) {
	empty, err := a.store.InstanceEmpty(ctx)
	if err != nil {
		return nil, err
	}
	if !empty {
		return nil, ErrBootstrapClosed
	}
	request, err := a.opaque.Deserialize.RegistrationRequest(encodedRequest)
	if err != nil {
		return nil, err
	}
	response, err := a.opaque.RegistrationResponse(request, []byte(email), nil)
	if err != nil {
		return nil, err
	}
	return response.Serialize(), nil
}

func (a *AuthService) finish(ctx context.Context, accountID, email string, encodedRecord, passwordEnvelope, recoveryEnvelope []byte) error {
	if accountID == "" {
		return errors.New("account ID is required")
	}
	record, err := a.opaque.Deserialize.RegistrationRecord(encodedRecord)
	if err != nil {
		return err
	}
	return a.store.CreateBootstrap(ctx, BootstrapAccount{
		AccountID:             accountID,
		Email:                 email,
		Administrator:         true,
		OpaqueRecord:          record.Serialize(),
		PasswordVaultEnvelope: passwordEnvelope,
		RecoveryVaultEnvelope: recoveryEnvelope,
	})
}

type loginStartRequest struct {
	Email string `json:"email"`
	KE1   string `json:"ke1"`
}

type loginStartResponse struct {
	LoginID string `json:"login_id"`
	KE2     string `json:"ke2"`
}

type loginFinishRequest struct {
	LoginID string `json:"login_id"`
	KE3     string `json:"ke3"`
}

type loginFinishResponse struct {
	AccountID             string `json:"account_id"`
	PasswordVaultEnvelope string `json:"password_vault_envelope"`
	RecoveryVaultEnvelope string `json:"recovery_vault_envelope"`
}

func (a *AuthService) startLogin(w http.ResponseWriter, r *http.Request) {
	var request loginStartRequest
	if !decodeRequest(w, r, &request) {
		return
	}
	email, err := canonicalEmail(request.Email)
	if err != nil {
		http.Error(w, "invalid login request", http.StatusBadRequest)
		return
	}
	encoded, err := base64.RawStdEncoding.DecodeString(request.KE1)
	if err != nil {
		http.Error(w, "invalid login request", http.StatusBadRequest)
		return
	}
	loginID, response, err := a.beginLogin(r.Context(), email, encoded)
	if err != nil {
		http.Error(w, "invalid login request", http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, loginStartResponse{
		LoginID: loginID,
		KE2:     base64.RawStdEncoding.EncodeToString(response),
	})
}

func (a *AuthService) finishLogin(w http.ResponseWriter, r *http.Request) {
	var request loginFinishRequest
	if !decodeRequest(w, r, &request) {
		return
	}
	encoded, err := base64.RawStdEncoding.DecodeString(request.KE3)
	if err != nil {
		http.Error(w, "invalid login", http.StatusUnauthorized)
		return
	}
	account, err := a.completeLogin(request.LoginID, encoded)
	if err != nil {
		http.Error(w, "invalid login", http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, loginFinishResponse{
		AccountID:             account.AccountID,
		PasswordVaultEnvelope: base64.RawStdEncoding.EncodeToString(account.PasswordVaultEnvelope),
		RecoveryVaultEnvelope: base64.RawStdEncoding.EncodeToString(account.RecoveryVaultEnvelope),
	})
}

func (a *AuthService) beginLogin(ctx context.Context, email string, encodedKE1 []byte) (string, []byte, error) {
	ke1, err := a.opaque.Deserialize.KE1(encodedKE1)
	if err != nil {
		return "", nil, err
	}
	account, err := a.store.FindAccount(ctx, email)
	var record *opaque.ClientRecord
	var accountPtr *StoredAccount
	switch {
	case errors.Is(err, ErrAccountNotFound):
		record, err = a.config.GetFakeRecord([]byte(email))
	case err != nil:
		return "", nil, err
	default:
		registrationRecord, decodeErr := a.opaque.Deserialize.RegistrationRecord(account.OpaqueRecord)
		if decodeErr != nil {
			return "", nil, decodeErr
		}
		record = &opaque.ClientRecord{
			RegistrationRecord:   registrationRecord,
			CredentialIdentifier: []byte(email),
			ClientIdentity:       []byte(email),
		}
		accountPtr = &account
	}
	if err != nil {
		return "", nil, err
	}
	ke2, output, err := a.opaque.GenerateKE2(ke1, record)
	if err != nil {
		return "", nil, err
	}
	loginID, err := newLoginID()
	if err != nil {
		clearBytes(output.ClientMAC)
		clearBytes(output.SessionSecret)
		return "", nil, err
	}
	a.mu.Lock()
	a.pending[loginID] = pendingLogin{
		account:       accountPtr,
		clientMAC:     output.ClientMAC,
		sessionSecret: output.SessionSecret,
		expiresAt:     time.Now().Add(5 * time.Minute),
	}
	a.mu.Unlock()
	return loginID, ke2.Serialize(), nil
}

func (a *AuthService) completeLogin(loginID string, encodedKE3 []byte) (*StoredAccount, error) {
	a.mu.Lock()
	pending, ok := a.pending[loginID]
	delete(a.pending, loginID)
	a.mu.Unlock()
	if !ok || time.Now().After(pending.expiresAt) {
		return nil, errInvalidLogin
	}
	defer clearBytes(pending.clientMAC)
	defer clearBytes(pending.sessionSecret)
	ke3, err := a.opaque.Deserialize.KE3(encodedKE3)
	if err != nil {
		return nil, errInvalidLogin
	}
	if err := a.opaque.LoginFinish(ke3, pending.clientMAC); err != nil || pending.account == nil {
		return nil, errInvalidLogin
	}
	return pending.account, nil
}

func newLoginID() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate login ID: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func newAccountID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate account ID: %w", err)
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}

func canonicalEmail(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	parsed, err := mail.ParseAddress(value)
	if err != nil || parsed.Address != value {
		return "", errors.New("invalid email")
	}
	return value, nil
}

func decodeRequest(w http.ResponseWriter, r *http.Request, target any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 128<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		http.Error(w, "invalid bootstrap request", http.StatusBadRequest)
		return false
	}
	if decoder.More() {
		http.Error(w, "invalid bootstrap request", http.StatusBadRequest)
		return false
	}
	return true
}

func writeBootstrapError(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrBootstrapClosed) {
		http.Error(w, "bootstrap registration is closed", http.StatusConflict)
		return
	}
	http.Error(w, "invalid bootstrap request", http.StatusBadRequest)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func clearBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
