package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type syncRequest struct {
	Cursor    string     `json:"cursor"`
	Mutations []Mutation `json:"mutations"`
}

type syncResponse struct {
	Cursor             string          `json:"cursor"`
	FullSnapshot       bool            `json:"full_snapshot"`
	AppliedMutationIDs []string        `json:"applied_mutation_ids"`
	Changes            []EncryptedItem `json:"changes"`
}

func SyncCache(
	ctx context.Context,
	cfg Config,
	accessToken string,
	cache *Cache,
) error {
	if accessToken == "" {
		return errors.New("access token is required")
	}
	if cache == nil {
		return errors.New("encrypted cache is required")
	}
	if err := validateServerURL(cfg.ServerURL); err != nil {
		return err
	}
	httpClient, err := newHTTPClient(cfg)
	if err != nil {
		return err
	}
	snapshot, err := cache.SyncSnapshot()
	if err != nil {
		return err
	}
	payload, err := json.Marshal(syncRequest{
		Cursor:    snapshot.Cursor,
		Mutations: snapshot.Mutations,
	})
	if err != nil {
		return fmt.Errorf("encode synchronization request: %w", err)
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		strings.TrimRight(cfg.ServerURL, "/")+"/api/v1/sync",
		bytes.NewReader(payload),
	)
	if err != nil {
		return fmt.Errorf("build synchronization request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+accessToken)
	request.Header.Set("Content-Type", "application/json")
	response, err := httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("synchronize cache: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf(
			"synchronize cache: server returned HTTP %d",
			response.StatusCode,
		)
	}
	var body syncResponse
	decoder := json.NewDecoder(
		io.LimitReader(response.Body, maximumCacheFileSize+1))
	if err := decoder.Decode(&body); err != nil {
		return fmt.Errorf("decode synchronization response: %w", err)
	}
	if err := cache.ApplySyncResult(SyncResult{
		Cursor:             body.Cursor,
		FullSnapshot:       body.FullSnapshot,
		AppliedMutationIDs: body.AppliedMutationIDs,
		Changes:            body.Changes,
	}); err != nil {
		return fmt.Errorf("apply synchronization response: %w", err)
	}
	return nil
}
