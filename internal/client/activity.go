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

type AuditEvent struct {
	EventID    string    `json:"event_id"`
	Type       string    `json:"type"`
	AccountID  string    `json:"account_id,omitempty"`
	ActorID    string    `json:"actor_id,omitempty"`
	SessionID  string    `json:"session_id,omitempty"`
	InviteID   string    `json:"invite_id,omitempty"`
	SourceIP   string    `json:"source_ip,omitempty"`
	OccurredAt time.Time `json:"occurred_at"`
}

type ActivityPage struct {
	Events     []AuditEvent `json:"events"`
	NextCursor string       `json:"next_cursor"`
	CanViewAll bool         `json:"can_view_all"`
}

func ListActivity(
	ctx context.Context,
	cfg Config,
	accessToken string,
	allAccounts bool,
	cursor string,
) (ActivityPage, error) {
	if accessToken == "" {
		return ActivityPage{}, errors.New("access token is required")
	}
	if err := validateServerURL(cfg.ServerURL); err != nil {
		return ActivityPage{}, err
	}
	httpClient, err := newHTTPClient(cfg)
	if err != nil {
		return ActivityPage{}, err
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	path := "/api/v1/activity"
	if allAccounts {
		path = "/api/v1/admin/activity"
	}
	endpoint, err := url.Parse(cfg.ServerURL + path)
	if err != nil {
		return ActivityPage{}, fmt.Errorf("build activity URL: %w", err)
	}
	if cursor != "" {
		query := endpoint.Query()
		query.Set("cursor", cursor)
		endpoint.RawQuery = query.Encode()
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return ActivityPage{}, fmt.Errorf("build activity request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+accessToken)
	response, err := httpClient.Do(request)
	if err != nil {
		return ActivityPage{}, fmt.Errorf("list activity: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return ActivityPage{}, fmt.Errorf("list activity: server returned HTTP %d", response.StatusCode)
	}
	var page ActivityPage
	if err := json.NewDecoder(response.Body).Decode(&page); err != nil {
		return ActivityPage{}, fmt.Errorf("decode activity: %w", err)
	}
	return page, nil
}
