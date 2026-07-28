package client

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeCAFile persists the test server's certificate as a PEM trust anchor.
func writeCAFile(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	cert := srv.Certificate()
	if cert == nil {
		t.Fatal("server has no certificate")
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func statusHandlerStub(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":         "ok",
		"version":        "test",
		"schema_version": 3,
		"client_ip":      "127.0.0.1",
	})
}

func TestCheckStatusHealthy(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(statusHandlerStub))
	defer srv.Close()

	st, err := CheckStatus(context.Background(), Config{
		ServerURL:  srv.URL,
		CACertFile: writeCAFile(t, srv),
		Timeout:    5 * time.Second,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if st.State != StateHealthy {
		t.Fatalf("want healthy, got %v (%s)", st.State, st.Detail)
	}
	if st.Version != "test" || st.SchemaVersion != 3 {
		t.Errorf("unexpected payload: %+v", st)
	}
}

func TestCheckStatusTLSFailure(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(statusHandlerStub))
	defer srv.Close()

	// No CA file: the self-signed test certificate must fail validation.
	st, err := CheckStatus(context.Background(), Config{
		ServerURL: srv.URL,
		Timeout:   5 * time.Second,
	})
	if err != nil {
		t.Fatalf("classification errors are carried in Status, not returned: %v", err)
	}
	if st.State != StateTLSError {
		t.Fatalf("want tls-error, got %v (%s)", st.State, st.Detail)
	}
}

func TestCheckStatusUnreachable(t *testing.T) {
	// Bind and immediately close to guarantee a refused connection.
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := lis.Addr().String()
	_ = lis.Close()

	st, err := CheckStatus(context.Background(), Config{
		ServerURL: "https://" + addr,
		Timeout:   2 * time.Second,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if st.State != StateUnreachable {
		t.Fatalf("want unreachable, got %v (%s)", st.State, st.Detail)
	}
}

func TestCheckStatusServerUnhealthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	st, err := CheckStatus(context.Background(), Config{
		ServerURL: srv.URL, // plain HTTP on localhost is permitted
		Timeout:   5 * time.Second,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if st.State != StateUnavailable {
		t.Fatalf("want unavailable, got %v (%s)", st.State, st.Detail)
	}
}

func TestCheckStatusRejectsPlainHTTPOutsideLocalhost(t *testing.T) {
	_, err := CheckStatus(context.Background(), Config{
		ServerURL: "http://termkeep.example.com",
		Timeout:   time.Second,
	})
	if err == nil {
		t.Fatal("want insecure-scheme error, got nil")
	}
}

func TestConnectivityStatesHaveDistinctOperatorLabels(t *testing.T) {
	tests := []struct {
		state State
		want  string
	}{
		{state: StateClientOffline, want: "Status:   Client offline"},
		{state: StateServerUnavailable, want: "Status:   Server unavailable"},
		{state: StateTLSError, want: "Status:   TLS validation failed"},
		{state: StateConnectionUnavailable, want: "Status:   Connection unavailable"},
	}
	for _, test := range tests {
		t.Run(test.want, func(t *testing.T) {
			lines := strings.Join(Lines("https://vault.example.com", Status{
				State:  test.state,
				Detail: "classified detail",
			}), "\n")
			if !strings.Contains(lines, test.want) {
				t.Fatalf("connection label missing:\n%s", lines)
			}
		})
	}
}
