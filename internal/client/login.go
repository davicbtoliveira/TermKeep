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

// LoginInput is entered locally. MasterPassword remains inside the OPAQUE
// client and is never serialized into a request.
type LoginInput struct {
	Email          string
	MasterPassword string
	Host           string
}

// LoginResult contains an unlocked vault key held only by the caller.
type LoginResult struct {
	AccountID   string
	VaultKey    []byte
	AccessToken string
}

type loginStartBody struct {
	LoginID string `json:"login_id"`
	KE2     string `json:"ke2"`
}

type loginFinishBody struct {
	AccountID             string `json:"account_id"`
	PasswordVaultEnvelope string `json:"password_vault_envelope"`
	AccessToken           string `json:"access_token"`
}

// Login proves the master password with OPAQUE, then decrypts the returned
// client-encrypted vault envelope locally.
func Login(ctx context.Context, cfg Config, input LoginInput) (*LoginResult, error) {
	email, err := canonicalBootstrapEmail(input.Email)
	if err != nil {
		return nil, err
	}
	if input.MasterPassword == "" {
		return nil, errors.New("master password is required")
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
	ke1, err := opaqueClient.GenerateKE1(password)
	if err != nil {
		return nil, fmt.Errorf("start OPAQUE login: %w", err)
	}
	var start loginStartBody
	if err := postBootstrap(ctx, httpClient, cfg.ServerURL, "/api/v1/login/start", map[string]string{
		"email": email,
		"ke1":   base64.RawStdEncoding.EncodeToString(ke1.Serialize()),
		"host":  input.Host,
	}, http.StatusOK, &start); err != nil {
		return nil, err
	}
	ke2Bytes, err := base64.RawStdEncoding.DecodeString(start.KE2)
	if err != nil {
		return nil, errors.New("login response contains invalid OPAQUE message")
	}
	ke2, err := opaqueClient.Deserialize.KE2(ke2Bytes)
	if err != nil {
		return nil, fmt.Errorf("decode OPAQUE login response: %w", err)
	}
	ke3, sessionKey, exportKey, err := opaqueClient.GenerateKE3(ke2, []byte(email), nil)
	if err != nil {
		_ = postBootstrap(
			ctx,
			httpClient,
			cfg.ServerURL,
			"/api/v1/login/fail",
			map[string]string{"login_id": start.LoginID},
			http.StatusNoContent,
			nil,
		)
		return nil, errors.New("invalid email or master password")
	}
	defer clearBytes(sessionKey)
	defer clearBytes(exportKey)

	var finish loginFinishBody
	if err := postBootstrap(ctx, httpClient, cfg.ServerURL, "/api/v1/login/finish", map[string]string{
		"login_id": start.LoginID,
		"ke3":      base64.RawStdEncoding.EncodeToString(ke3.Serialize()),
	}, http.StatusOK, &finish); err != nil {
		return nil, errors.New("invalid email or master password")
	}
	if finish.AccountID == "" {
		return nil, errors.New("login response missing account ID")
	}
	if finish.AccessToken == "" {
		return nil, errors.New("login response missing access token")
	}
	envelope, err := base64.RawStdEncoding.DecodeString(finish.PasswordVaultEnvelope)
	if err != nil {
		return nil, errors.New("login response contains invalid vault envelope")
	}
	vaultKey, err := UnlockVaultWithPassword(envelope, password, finish.AccountID)
	if err != nil {
		return nil, errors.New("invalid email, master password, or vault envelope")
	}
	return &LoginResult{
		AccountID:   finish.AccountID,
		VaultKey:    vaultKey,
		AccessToken: finish.AccessToken,
	}, nil
}

// Clear makes a best-effort attempt to erase the unlocked vault key.
func (r *LoginResult) Clear() {
	clearBytes(r.VaultKey)
	r.VaultKey = nil
	r.AccessToken = ""
}
