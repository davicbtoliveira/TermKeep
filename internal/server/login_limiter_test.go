package server

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bytemare/opaque"
)

func TestLoginLimiterDelaysAfterFiveFailures(t *testing.T) {
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	limiter := NewLoginLimiter(func() time.Time { return now })

	for attempt := 1; attempt <= 4; attempt++ {
		limiter.RecordFailure("user@example.com", "192.0.2.10")
		if retry := limiter.RetryAfter("user@example.com", "192.0.2.10"); retry != 0 {
			t.Fatalf("failure %d delayed early by %s", attempt, retry)
		}
	}
	limiter.RecordFailure("user@example.com", "192.0.2.10")
	if retry := limiter.RetryAfter("user@example.com", "192.0.2.10"); retry != time.Minute {
		t.Fatalf("fifth failure delay: want 1m, got %s", retry)
	}
}

func TestLoginLimiterProgressesAndCapsDelays(t *testing.T) {
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	limiter := NewLoginLimiter(func() time.Time { return now })
	account, source := "user@example.com", "192.0.2.10"

	for range 5 {
		limiter.RecordFailure(account, source)
	}
	for _, want := range []time.Duration{5 * time.Minute, 10 * time.Minute, 15 * time.Minute, 15 * time.Minute} {
		now = now.Add(limiter.RetryAfter(account, source))
		limiter.RecordFailure(account, source)
		if retry := limiter.RetryAfter(account, source); retry != want {
			t.Fatalf("progressive delay: want %s, got %s", want, retry)
		}
	}
}

func TestLoginLimiterResetsAfterSuccess(t *testing.T) {
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	limiter := NewLoginLimiter(func() time.Time { return now })
	account, source := "user@example.com", "192.0.2.10"
	for range 5 {
		limiter.RecordFailure(account, source)
	}

	limiter.Reset(account, source)
	limiter.RecordFailure(account, source)
	if retry := limiter.RetryAfter(account, source); retry != 0 {
		t.Fatalf("failure after success delayed by %s", retry)
	}
}

func TestLoginLimiterResetsAfterTwentyFourHoursWithoutFailure(t *testing.T) {
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	limiter := NewLoginLimiter(func() time.Time { return now })
	account, source := "user@example.com", "192.0.2.10"
	for range 8 {
		limiter.RecordFailure(account, source)
	}

	now = now.Add(24 * time.Hour)
	limiter.RecordFailure(account, source)
	if retry := limiter.RetryAfter(account, source); retry != 0 {
		t.Fatalf("failure after 24 hours delayed by %s", retry)
	}
}

func TestLoginLimiterIsolatesAccountsAndOrigins(t *testing.T) {
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	limiter := NewLoginLimiter(func() time.Time { return now })
	for range 5 {
		limiter.RecordFailure("user@example.com", "192.0.2.10")
	}

	if retry := limiter.RetryAfter("user@example.com", "192.0.2.11"); retry != 0 {
		t.Fatalf("other origin delayed by %s", retry)
	}
	if retry := limiter.RetryAfter("other@example.com", "192.0.2.10"); retry != 0 {
		t.Fatalf("other account delayed by %s", retry)
	}
}

func TestLoginEndpointDelaysSixthAttempt(t *testing.T) {
	store := &memoryBootstrapStore{}
	auth := newTestAuthService(t, store)
	handler := NewHandler("test", stubSchema{version: 1}, nil, auth)
	server := httptest.NewServer(handler)
	defer server.Close()

	password := []byte("TermKeep#2026")
	mustBootstrap(t, server, "admin@example.com", password)
	for range 5 {
		response := startLoginAttempt(t, server, "admin@example.com", password)
		if response.StatusCode != http.StatusOK {
			t.Fatalf("first five attempts: want 200, got %d", response.StatusCode)
		}
		response.Body.Close()
	}
	response := startLoginAttempt(t, server, "admin@example.com", password)
	defer response.Body.Close()
	if response.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("sixth attempt: want 429, got %d", response.StatusCode)
	}
	if retry := response.Header.Get("Retry-After"); retry != "60" {
		t.Fatalf("Retry-After: want 60, got %q", retry)
	}
}

func TestSuccessfulLoginResetsEndpointLimit(t *testing.T) {
	store := &memoryBootstrapStore{}
	auth := newTestAuthService(t, store)
	handler := NewHandler("test", stubSchema{version: 1}, nil, auth)
	server := httptest.NewServer(handler)
	defer server.Close()

	password := []byte("TermKeep#2026")
	mustBootstrap(t, server, "admin@example.com", password)
	for range 4 {
		response := startLoginAttempt(t, server, "admin@example.com", password)
		response.Body.Close()
	}
	mustLogin(t, server, "admin@example.com", password)

	response := startLoginAttempt(t, server, "admin@example.com", password)
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("attempt after successful login: want 200, got %d", response.StatusCode)
	}
}

func TestMissingAndExistingAccountsShareLoginLimitResponse(t *testing.T) {
	store := &memoryBootstrapStore{}
	auth := newTestAuthService(t, store)
	handler := NewHandler("test", stubSchema{version: 1}, nil, auth)
	server := httptest.NewServer(handler)
	defer server.Close()

	password := []byte("TermKeep#2026")
	mustBootstrap(t, server, "admin@example.com", password)
	for range 5 {
		existing := startLoginAttempt(t, server, "admin@example.com", password)
		existing.Body.Close()
		missing := startLoginAttempt(t, server, "missing@example.com", password)
		missing.Body.Close()
	}

	existing := startLoginAttempt(t, server, "admin@example.com", password)
	defer existing.Body.Close()
	missing := startLoginAttempt(t, server, "missing@example.com", password)
	defer missing.Body.Close()
	if existing.StatusCode != missing.StatusCode || existing.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("limit statuses differ: existing=%d missing=%d", existing.StatusCode, missing.StatusCode)
	}
	if existing.Header.Get("Retry-After") != missing.Header.Get("Retry-After") {
		t.Fatalf("Retry-After differs: existing=%q missing=%q",
			existing.Header.Get("Retry-After"), missing.Header.Get("Retry-After"))
	}
}

func startLoginAttempt(t *testing.T, server *httptest.Server, email string, password []byte) *http.Response {
	return startLoginAttemptFromHost(t, server, email, password, "")
}

func startLoginAttemptFromHost(t *testing.T, server *httptest.Server, email string, password []byte, host string) *http.Response {
	t.Helper()
	client, err := opaque.NewClient(nil)
	if err != nil {
		t.Fatal(err)
	}
	ke1, err := client.GenerateKE1(password)
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]string{
		"email": email,
		"ke1":   base64.RawStdEncoding.EncodeToString(ke1.Serialize()),
	}
	if host != "" {
		body["host"] = host
	}
	return postJSON(t, server.URL+"/api/v1/login/start", body)
}
