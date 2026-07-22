package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/bytemare/opaque"
)

var ErrMasterPasswordConfirmation = errors.New("master password confirmation does not match")

// BootstrapInput is entered locally. MasterPassword fields never appear in an
// HTTP payload, database record, log field, or returned result.
type BootstrapInput struct {
	Email                 string
	MasterPassword        string
	ConfirmMasterPassword string
}

// BootstrapResult contains the unlocked empty vault plus its recovery key.
// The CLI displays RecoveryKey once and callers must clear Vault when done.
type BootstrapResult struct {
	AccountID   string
	RecoveryKey string
	Vault       *Vault
}

type bootstrapStartBody struct {
	AccountID            string `json:"account_id"`
	RegistrationResponse string `json:"registration_response"`
}

// Bootstrap completes first-account OPAQUE registration, creates the vault
// locally, and stores only opaque registration material and encrypted vault
// envelopes on the server.
func Bootstrap(ctx context.Context, cfg Config, input BootstrapInput) (*BootstrapResult, error) {
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
	if err := postBootstrap(ctx, httpClient, cfg.ServerURL, "/api/v1/bootstrap/start", map[string]string{
		"email":                email,
		"registration_request": base64.RawStdEncoding.EncodeToString(registrationRequest.Serialize()),
	}, http.StatusOK, &start); err != nil {
		return nil, err
	}
	if start.AccountID == "" {
		return nil, errors.New("bootstrap response missing account ID")
	}
	registrationResponse, err := base64.RawStdEncoding.DecodeString(start.RegistrationResponse)
	if err != nil {
		return nil, errors.New("bootstrap response contains invalid OPAQUE message")
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
	if err := postBootstrap(ctx, httpClient, cfg.ServerURL, "/api/v1/bootstrap/finish", map[string]string{
		"account_id":              start.AccountID,
		"email":                   email,
		"registration_record":     base64.RawStdEncoding.EncodeToString(record.Serialize()),
		"password_vault_envelope": base64.RawStdEncoding.EncodeToString(vault.PasswordEnvelope),
		"recovery_vault_envelope": base64.RawStdEncoding.EncodeToString(vault.RecoveryEnvelope),
	}, http.StatusCreated, nil); err != nil {
		vault.Clear()
		return nil, err
	}
	return &BootstrapResult{
		AccountID:   start.AccountID,
		RecoveryKey: vault.RecoveryKey,
		Vault:       vault,
	}, nil
}

func postBootstrap(ctx context.Context, client *http.Client, baseURL, path string, value any, expectedStatus int, output any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode request: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(baseURL, "/")+path, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != expectedStatus {
		return fmt.Errorf("server returned HTTP %d", response.StatusCode)
	}
	if output != nil {
		if err := json.NewDecoder(response.Body).Decode(output); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

func canonicalBootstrapEmail(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	parsed, err := mail.ParseAddress(value)
	if err != nil || parsed.Address != value {
		return "", errors.New("invalid email")
	}
	return value, nil
}
