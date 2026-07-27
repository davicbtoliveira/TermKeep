package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestListActivityReturnsAuthenticatedEventPage(t *testing.T) {
	occurredAt := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/activity" ||
			r.Header.Get("Authorization") != "Bearer access-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"events": []map[string]any{{
				"event_id":    "event-123",
				"type":        "login.succeeded",
				"account_id":  "account-123",
				"actor_id":    "account-123",
				"source_ip":   "192.0.2.10",
				"occurred_at": occurredAt,
			}},
			"next_cursor": "next-page",
		})
	}))
	defer server.Close()

	page, err := ListActivity(
		context.Background(), Config{ServerURL: server.URL}, "access-token", false, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Events) != 1 ||
		page.Events[0].Type != "login.succeeded" ||
		page.Events[0].ActorID != "account-123" ||
		page.NextCursor != "next-page" {
		t.Fatalf("unexpected activity page: %+v", page)
	}
}
