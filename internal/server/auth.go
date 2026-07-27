package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/bytemare/opaque"
)

var ErrBootstrapClosed = errors.New("bootstrap registration is closed")
var ErrAccountNotFound = errors.New("account not found")
var ErrAccessTokenNotFound = errors.New("access token not found")

var errInvalidLogin = errors.New("invalid login")
var errInvalidAccessToken = errors.New("invalid access token")

// BootstrapStore persists the first account and its opaque client-created
// vault envelopes. CreateBootstrap must reject concurrent second attempts.
type BootstrapStore interface {
	InstanceEmpty(ctx context.Context) (bool, error)
	CreateBootstrap(ctx context.Context, account BootstrapAccount) error
	FindAccount(ctx context.Context, email string) (StoredAccount, error)
}

// AccessTokenStore persists only the SHA-256 hash of bearer tokens. The
// plaintext token is returned once at login and never stored.
type AccessTokenStore interface {
	CreateAccessToken(ctx context.Context, token StoredAccessToken) error
	FindAccessToken(ctx context.Context, tokenHash []byte) (StoredAccessToken, error)
	TouchAccessToken(ctx context.Context, tokenHash []byte, now time.Time) error
}

// InvitedRegistrationStore validates and atomically consumes invitations
// while creating non-administrator accounts.
type InvitedRegistrationStore interface {
	ValidateInvite(ctx context.Context, tokenHash []byte, email string, now time.Time) error
	CreateInvitedAccount(ctx context.Context, tokenHash []byte, account BootstrapAccount, now time.Time) error
}

// AuthStore is the full persistence boundary of AuthService.
type AuthStore interface {
	BootstrapStore
	AccessTokenStore
	InvitedRegistrationStore
}

// StoredAccessToken resolves a bearer token hash to its account. The
// Administrator flag authorizes the invitation management surface.
type StoredAccessToken struct {
	TokenHash     []byte
	SessionID     string
	AccountID     string
	Email         string
	Administrator bool
	Host          string
	SourceIP      string
	CreatedAt     time.Time
	LastUsedAt    time.Time
	RevokedAt     time.Time
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
	Administrator         bool
	OpaqueRecord          []byte
	PasswordVaultEnvelope []byte
	RecoveryVaultEnvelope []byte
}

// AuthService implements bootstrap registration while keeping OPAQUE protocol
// details out of the HTTP handler.
type AuthService struct {
	opaque  *opaque.Server
	config  *opaque.Configuration
	store   AuthStore
	audit   *AuditLog
	limiter *LoginLimiter
	mu      sync.Mutex
	pending map[string]pendingLogin
}

type pendingLogin struct {
	account       *StoredAccount
	clientMAC     []byte
	sessionSecret []byte
	host          string
	sourceIP      string
	rateAccount   string
	expiresAt     time.Time
}

// NewAuthService configures the OPAQUE server and persistence boundary used by
// registration and later authentication flows.
func NewAuthService(opaqueServer *opaque.Server, store AuthStore, auditLogs ...*AuditLog) *AuthService {
	var audit *AuditLog
	if len(auditLogs) > 0 {
		audit = auditLogs[0]
	}
	return &AuthService{
		opaque:  opaqueServer,
		config:  opaque.DefaultConfiguration(),
		store:   store,
		audit:   audit,
		limiter: NewLoginLimiter(time.Now),
		pending: make(map[string]pendingLogin),
	}
}

func (a *AuthService) register(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/bootstrap/start", a.startBootstrap)
	mux.HandleFunc("POST /api/v1/bootstrap/finish", a.finishBootstrap)
	mux.HandleFunc("POST /api/v1/register/start", a.startRegistration)
	mux.HandleFunc("POST /api/v1/register/finish", a.finishRegistration)
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

type registrationStartRequest struct {
	Email               string `json:"email"`
	InviteToken         string `json:"invite_token"`
	RegistrationRequest string `json:"registration_request"`
}

type registrationFinishRequest struct {
	AccountID             string `json:"account_id"`
	Email                 string `json:"email"`
	InviteToken           string `json:"invite_token"`
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

func (a *AuthService) startRegistration(w http.ResponseWriter, r *http.Request) {
	var request registrationStartRequest
	if !decodeRequest(w, r, &request) {
		return
	}
	email, err := canonicalEmail(request.Email)
	if err != nil {
		http.Error(w, "invalid registration request", http.StatusBadRequest)
		return
	}
	tokenHash, err := inviteTokenHash(request.InviteToken)
	if err != nil {
		http.Error(w, "invalid invitation", http.StatusUnauthorized)
		return
	}
	if err := a.store.ValidateInvite(r.Context(), tokenHash, email, time.Now()); err != nil {
		writeRegistrationError(w, err)
		return
	}
	encoded, err := base64.RawStdEncoding.DecodeString(request.RegistrationRequest)
	if err != nil {
		http.Error(w, "invalid registration request", http.StatusBadRequest)
		return
	}
	response, err := a.registrationResponse(email, encoded)
	if err != nil {
		http.Error(w, "invalid registration request", http.StatusBadRequest)
		return
	}
	accountID, err := newAccountID()
	if err != nil {
		http.Error(w, "registration unavailable", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, bootstrapStartResponse{
		AccountID:            accountID,
		RegistrationResponse: base64.RawStdEncoding.EncodeToString(response),
	})
}

func (a *AuthService) finishRegistration(w http.ResponseWriter, r *http.Request) {
	var request registrationFinishRequest
	if !decodeRequest(w, r, &request) {
		return
	}
	email, err := canonicalEmail(request.Email)
	if err != nil {
		http.Error(w, "invalid registration request", http.StatusBadRequest)
		return
	}
	tokenHash, err := inviteTokenHash(request.InviteToken)
	if err != nil {
		http.Error(w, "invalid invitation", http.StatusUnauthorized)
		return
	}
	record, err := base64.RawStdEncoding.DecodeString(request.RegistrationRecord)
	if err != nil {
		http.Error(w, "invalid registration request", http.StatusBadRequest)
		return
	}
	passwordEnvelope, err := base64.RawStdEncoding.DecodeString(request.PasswordVaultEnvelope)
	if err != nil || len(passwordEnvelope) == 0 {
		http.Error(w, "invalid registration request", http.StatusBadRequest)
		return
	}
	recoveryEnvelope, err := base64.RawStdEncoding.DecodeString(request.RecoveryVaultEnvelope)
	if err != nil || len(recoveryEnvelope) == 0 {
		http.Error(w, "invalid registration request", http.StatusBadRequest)
		return
	}
	registrationRecord, err := a.opaque.Deserialize.RegistrationRecord(record)
	if err != nil {
		http.Error(w, "invalid registration request", http.StatusBadRequest)
		return
	}
	if request.AccountID == "" {
		http.Error(w, "invalid registration request", http.StatusBadRequest)
		return
	}
	now := time.Now()
	err = a.store.CreateInvitedAccount(r.Context(), tokenHash, BootstrapAccount{
		AccountID:             request.AccountID,
		Email:                 email,
		Administrator:         false,
		OpaqueRecord:          registrationRecord.Serialize(),
		PasswordVaultEnvelope: passwordEnvelope,
		RecoveryVaultEnvelope: recoveryEnvelope,
	}, now)
	if err != nil {
		writeRegistrationError(w, err)
		return
	}
	recordAudit(r.Context(), a.audit, AuditEvent{
		Type:       "registration.succeeded",
		AccountID:  request.AccountID,
		ActorID:    request.AccountID,
		SourceIP:   requestClientIP(r),
		OccurredAt: now,
	})
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
	return a.registrationResponse(email, encodedRequest)
}

func (a *AuthService) registrationResponse(email string, encodedRequest []byte) ([]byte, error) {
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
	Host  string `json:"host,omitempty"`
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
	AccessToken           string `json:"access_token"`
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
	host := strings.TrimSpace(request.Host)
	if host == "" {
		host = "unknown"
	}
	if !validSessionHost(host) {
		http.Error(w, "invalid login request", http.StatusBadRequest)
		return
	}
	sourceIP := requestClientIP(r)
	if retry := a.limiter.RetryAfter(email, sourceIP); retry > 0 {
		var accountID string
		if account, err := a.store.FindAccount(r.Context(), email); err == nil {
			accountID = account.AccountID
		}
		recordAudit(r.Context(), a.audit, AuditEvent{
			Type:      "login.throttled",
			AccountID: accountID,
			SourceIP:  sourceIP,
		})
		seconds := (retry + time.Second - 1) / time.Second
		w.Header().Set("Retry-After", strconv.FormatInt(int64(seconds), 10))
		http.Error(w, "login temporarily delayed", http.StatusTooManyRequests)
		return
	}
	loginID, response, err := a.beginLogin(r.Context(), email, encoded, host, sourceIP)
	if err != nil {
		http.Error(w, "invalid login request", http.StatusBadRequest)
		return
	}
	a.limiter.RecordFailure(email, sourceIP)
	writeJSON(w, http.StatusOK, loginStartResponse{
		LoginID: loginID,
		KE2:     base64.RawStdEncoding.EncodeToString(response),
	})
}

func validSessionHost(host string) bool {
	if len(host) > 255 {
		return false
	}
	for _, character := range host {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
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
	login, err := a.completeLogin(request.LoginID, encoded)
	if err != nil {
		var accountID string
		if login.account != nil {
			accountID = login.account.AccountID
		}
		recordAudit(r.Context(), a.audit, AuditEvent{
			Type:      "login.failed",
			AccountID: accountID,
			SourceIP:  login.sourceIP,
		})
		http.Error(w, "invalid login", http.StatusUnauthorized)
		return
	}
	a.limiter.Reset(login.rateAccount, login.sourceIP)
	token, err := a.issueAccessToken(r.Context(), login.account, login.host, login.sourceIP)
	if err != nil {
		http.Error(w, "login unavailable", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, loginFinishResponse{
		AccountID:             login.account.AccountID,
		PasswordVaultEnvelope: base64.RawStdEncoding.EncodeToString(login.account.PasswordVaultEnvelope),
		RecoveryVaultEnvelope: base64.RawStdEncoding.EncodeToString(login.account.RecoveryVaultEnvelope),
		AccessToken:           token,
	})
}

func (a *AuthService) issueAccessToken(ctx context.Context, account *StoredAccount, host, sourceIP string) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate access token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(token))
	sessionID, err := newAccountID()
	if err != nil {
		return "", err
	}
	now := time.Now()
	stored := StoredAccessToken{
		TokenHash:     hash[:],
		SessionID:     sessionID,
		AccountID:     account.AccountID,
		Email:         account.Email,
		Administrator: account.Administrator,
		Host:          host,
		SourceIP:      sourceIP,
		CreatedAt:     now,
		LastUsedAt:    now,
	}
	if err := a.store.CreateAccessToken(ctx, stored); err != nil {
		return "", fmt.Errorf("store access token: %w", err)
	}
	recordAudit(ctx, a.audit, AuditEvent{
		Type:       "login.succeeded",
		AccountID:  account.AccountID,
		ActorID:    account.AccountID,
		SessionID:  sessionID,
		SourceIP:   sourceIP,
		OccurredAt: now,
	})
	recordAudit(ctx, a.audit, AuditEvent{
		Type:       "session.created",
		AccountID:  account.AccountID,
		ActorID:    account.AccountID,
		SessionID:  sessionID,
		SourceIP:   sourceIP,
		OccurredAt: now,
	})
	return token, nil
}

func (a *AuthService) AuthenticateToken(ctx context.Context, rawToken string) (StoredAccessToken, error) {
	if rawToken == "" {
		return StoredAccessToken{}, ErrAccessTokenNotFound
	}
	hash := sha256.Sum256([]byte(rawToken))
	token, err := a.store.FindAccessToken(ctx, hash[:])
	if err != nil {
		return StoredAccessToken{}, err
	}
	if !token.RevokedAt.IsZero() {
		return StoredAccessToken{}, errInvalidAccessToken
	}
	now := time.Now()
	if err := a.store.TouchAccessToken(ctx, hash[:], now); err != nil {
		return StoredAccessToken{}, err
	}
	token.LastUsedAt = now
	return token, nil
}

func (a *AuthService) beginLogin(ctx context.Context, email string, encodedKE1 []byte, host, sourceIP string) (string, []byte, error) {
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
		host:          host,
		sourceIP:      sourceIP,
		rateAccount:   email,
		expiresAt:     time.Now().Add(5 * time.Minute),
	}
	a.mu.Unlock()
	return loginID, ke2.Serialize(), nil
}

func (a *AuthService) completeLogin(loginID string, encodedKE3 []byte) (pendingLogin, error) {
	a.mu.Lock()
	pending, ok := a.pending[loginID]
	delete(a.pending, loginID)
	a.mu.Unlock()
	if !ok || time.Now().After(pending.expiresAt) {
		return pending, errInvalidLogin
	}
	defer clearBytes(pending.clientMAC)
	defer clearBytes(pending.sessionSecret)
	ke3, err := a.opaque.Deserialize.KE3(encodedKE3)
	if err != nil {
		return pending, errInvalidLogin
	}
	if err := a.opaque.LoginFinish(ke3, pending.clientMAC); err != nil || pending.account == nil {
		return pending, errInvalidLogin
	}
	return pending, nil
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

func inviteTokenHash(value string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) != 32 {
		return nil, ErrInvalidInvite
	}
	hash := sha256.Sum256([]byte(value))
	return hash[:], nil
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

func writeRegistrationError(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrInvalidInvite) {
		http.Error(w, "invalid invitation", http.StatusUnauthorized)
		return
	}
	http.Error(w, "registration unavailable", http.StatusServiceUnavailable)
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
