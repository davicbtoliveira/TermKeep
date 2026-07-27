package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

type OnlineSession struct {
	SessionID string    `json:"session_id"`
	Host      string    `json:"host"`
	SourceIP  string    `json:"source_ip"`
	CreatedAt time.Time `json:"created_at"`
	LastUsed  time.Time `json:"last_used_at"`
	Current   bool      `json:"current"`
}

// RevokeSession ends one online session belonging to the authenticated
// account.
func RevokeSession(ctx context.Context, cfg Config, accessToken, sessionID string) error {
	if accessToken == "" {
		return errors.New("access token is required")
	}
	if sessionID == "" {
		return errors.New("session ID is required")
	}
	if err := validateServerURL(cfg.ServerURL); err != nil {
		return err
	}
	httpClient, err := newHTTPClient(cfg)
	if err != nil {
		return err
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodDelete,
		cfg.ServerURL+"/api/v1/sessions/"+url.PathEscape(sessionID),
		nil,
	)
	if err != nil {
		return fmt.Errorf("build revoke session request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+accessToken)
	response, err := httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("revoke session: server returned HTTP %d", response.StatusCode)
	}
	return nil
}

// ListSessions returns active online sessions for the authenticated account.
func ListSessions(ctx context.Context, cfg Config, accessToken string) ([]OnlineSession, error) {
	if accessToken == "" {
		return nil, errors.New("access token is required")
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

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.ServerURL+"/api/v1/sessions", nil)
	if err != nil {
		return nil, fmt.Errorf("build list sessions request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+accessToken)
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list sessions: server returned HTTP %d", response.StatusCode)
	}
	var body struct {
		Sessions []OnlineSession `json:"sessions"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode sessions: %w", err)
	}
	return body.Sessions, nil
}
