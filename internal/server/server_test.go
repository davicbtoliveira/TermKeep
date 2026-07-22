package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

type stubSchema struct {
	version int
	err     error
}

func (s stubSchema) SchemaVersion(context.Context) (int, error) {
	return s.version, s.err
}

func mustPrefixes(t *testing.T, cidrs ...string) []netip.Prefix {
	t.Helper()
	var out []netip.Prefix
	for _, c := range cidrs {
		out = append(out, netip.MustParsePrefix(c))
	}
	return out
}

func getStatus(t *testing.T, srv *httptest.Server, remoteAddr, xff string) (int, StatusResponse) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/status", nil)
	if err != nil {
		t.Fatal(err)
	}
	if remoteAddr != "" {
		req.RemoteAddr = remoteAddr
	}
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	// httptest.NewServer client cannot set RemoteAddr; use direct handler call instead.
	rec := httptest.NewRecorder()
	srv.Config.Handler.ServeHTTP(rec, req)
	res := rec.Result()
	defer res.Body.Close()
	var body StatusResponse
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode status response: %v", err)
	}
	return res.StatusCode, body
}

func TestStatusHealthy(t *testing.T) {
	h := NewHandler("dev", stubSchema{version: 1}, nil)
	srv := httptest.NewServer(h)
	defer srv.Close()

	code, body := getStatus(t, srv, "192.0.2.10:1234", "")
	if code != http.StatusOK {
		t.Fatalf("want 200, got %d", code)
	}
	if body.Status != "ok" {
		t.Errorf("status: want ok, got %q", body.Status)
	}
	if body.Version != "dev" {
		t.Errorf("version: want dev, got %q", body.Version)
	}
	if body.SchemaVersion != 1 {
		t.Errorf("schema_version: want 1, got %d", body.SchemaVersion)
	}
	if body.ClientIP != "192.0.2.10" {
		t.Errorf("client_ip: want 192.0.2.10, got %q", body.ClientIP)
	}
}

func TestStatusDatabaseDown(t *testing.T) {
	h := NewHandler("dev", stubSchema{err: errors.New("connection refused")}, nil)
	srv := httptest.NewServer(h)
	defer srv.Close()

	code, body := getStatus(t, srv, "192.0.2.10:1234", "")
	if code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d", code)
	}
	if body.Status != "unavailable" {
		t.Errorf("status: want unavailable, got %q", body.Status)
	}
}

func TestStatusIgnoresForwardedHeaderFromUntrustedSource(t *testing.T) {
	trusted := mustPrefixes(t, "10.0.0.0/8")
	h := NewHandler("dev", stubSchema{version: 1}, trusted)
	srv := httptest.NewServer(h)
	defer srv.Close()

	_, body := getStatus(t, srv, "192.0.2.10:1234", "203.0.113.99")
	if body.ClientIP != "192.0.2.10" {
		t.Errorf("forged X-Forwarded-For honored: client_ip = %q", body.ClientIP)
	}
}

func TestStatusHonorsForwardedHeaderFromTrustedProxy(t *testing.T) {
	trusted := mustPrefixes(t, "10.0.0.0/8")
	h := NewHandler("dev", stubSchema{version: 1}, trusted)
	srv := httptest.NewServer(h)
	defer srv.Close()

	_, body := getStatus(t, srv, "10.1.2.3:443", "203.0.113.99, 10.1.2.3")
	if body.ClientIP != "203.0.113.99" {
		t.Errorf("client_ip: want 203.0.113.99, got %q", body.ClientIP)
	}
}
