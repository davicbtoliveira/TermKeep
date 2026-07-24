package client

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/bytemare/opaque"
)

// RegisterInput is entered locally by an invited user. The master password
// never appears in an HTTP payload; only the OPAQUE messages leave the client.
type RegisterInput struct {
	Email                 string
	InviteToken           string
	MasterPassword        string
	ConfirmMasterPassword string
}

// RegisterResult contains the invited account's unlocked empty vault and the
// recovery key that the CLI displays once.
type RegisterResult struct {
	AccountID   string
	RecoveryKey string
	Vault       *Vault
}

// Register completes invited OPAQUE registration and creates a vault whose
// key and recovery material exist only on the client.
func Register(ctx context.Context, cfg Config, input RegisterInput) (*RegisterResult, error) {
	if input.MasterPassword != input.ConfirmMasterPassword {
		return nil, ErrMasterPasswordConfirmation
	}
	if err := ValidateMasterPassword(input.MasterPassword); err != nil {
		return nil, err
	}
	email, err := canonicalBootstrapEmail(input.Email)
	if err != nil {
		return nil, err
	}
	if input.InviteToken == "" {
		return nil, errors.New("invite token is required")
	}
	if err := validateServerURL(cfg.ServerURL); err != nil {
		return nil, err
	}
	httpClient, err := newHTTPClient(cfg)
	if err != nil {
		return nil, err
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	password := []byte(input.MasterPassword)
	defer clearBytes(password)
	opaqueClient, err := opaque.NewClient(nil)
	if err != nil {
		return nil, fmt.Errorf("initialize OPAQUE client: %w", err)
	}
	defer opaqueClient.ClearState()

	registrationRequest, err := opaqueClient.RegistrationInit(password)
	if err != nil {
		return nil, fmt.Errorf("start OPAQUE registration: %w", err)
	}
	var start bootstrapStartBody
	if err := postBootstrap(ctx, httpClient, cfg.ServerURL, "/api/v1/register/start", map[string]string{
		"email":                email,
		"invite_token":         input.InviteToken,
		"registration_request": base64.RawStdEncoding.EncodeToString(registrationRequest.Serialize()),
	}, http.StatusOK, &start); err != nil {
		return nil, err
	}
	if start.AccountID == "" {
		return nil, errors.New("registration response missing account ID")
	}
	registrationResponse, err := base64.RawStdEncoding.DecodeString(start.RegistrationResponse)
	if err != nil {
		return nil, errors.New("registration response contains invalid OPAQUE message")
	}
	response, err := opaqueClient.Deserialize.RegistrationResponse(registrationResponse)
	if err != nil {
		return nil, fmt.Errorf("decode OPAQUE registration response: %w", err)
	}
	record, _, err := opaqueClient.RegistrationFinalize(response, []byte(email), nil)
	if err != nil {
		return nil, fmt.Errorf("finish OPAQUE registration: %w", err)
	}
	vault, err := NewVault(password, start.AccountID)
	if err != nil {
		return nil, err
	}
	if err := postBootstrap(ctx, httpClient, cfg.ServerURL, "/api/v1/register/finish", map[string]string{
		"account_id":              start.AccountID,
		"email":                   email,
		"invite_token":            input.InviteToken,
		"registration_record":     base64.RawStdEncoding.EncodeToString(record.Serialize()),
		"password_vault_envelope": base64.RawStdEncoding.EncodeToString(vault.PasswordEnvelope),
		"recovery_vault_envelope": base64.RawStdEncoding.EncodeToString(vault.RecoveryEnvelope),
	}, http.StatusCreated, nil); err != nil {
		vault.Clear()
		return nil, err
	}
	return &RegisterResult{
		AccountID:   start.AccountID,
		RecoveryKey: vault.RecoveryKey,
		Vault:       vault,
	}, nil
}
