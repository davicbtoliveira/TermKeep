// Package client holds the TermKeep CLI's network behavior: how it talks to
// an instance and how it classifies the result for the operator.
package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"syscall"
	"time"
)

// State classifies what the client observed, per the PRD connectivity
// taxonomy: healthy, TLS security failure, or unavailability. TLS failures
// are never normalized as ordinary offline behavior.
type State int

const (
	StateHealthy State = iota
	StateClientOffline
	StateServerUnavailable
	StateTLSError
	StateConnectionUnavailable
)

// Compatibility aliases for callers built against the earlier coarse
// taxonomy.
const StateUnreachable = StateConnectionUnavailable
const StateUnavailable = StateServerUnavailable

// String renders the state for CLI and TUI output.
func (s State) String() string {
	switch s {
	case StateHealthy:
		return "healthy"
	case StateClientOffline:
		return "client-offline"
	case StateServerUnavailable:
		return "server-unavailable"
	case StateTLSError:
		return "tls-error"
	case StateConnectionUnavailable:
		return "connection-unavailable"
	default:
		return "unknown"
	}
}

// Status is the classified result of querying an instance.
type Status struct {
	State         State
	Version       string // server-reported version, when healthy
	SchemaVersion int    // server-reported schema version, when healthy
	Detail        string // human-readable explanation for non-healthy states
}

// Config controls how CheckStatus reaches the instance.
type Config struct {
	ServerURL  string        // base URL; HTTPS required outside localhost
	CACertFile string        // optional PEM trust anchor (self-hosted deployments)
	Timeout    time.Duration // overall request budget
	DataDir    string        // optional encrypted-cache directory
}

// statusBody mirrors the server's public status payload.
type statusBody struct {
	Status        string `json:"status"`
	Version       string `json:"version"`
	SchemaVersion int    `json:"schema_version"`
}

// CheckStatus queries GET /api/v1/status once and classifies the outcome.
// Network and TLS failures are reported inside Status, never as Go errors;
// a non-nil error means the configuration itself is invalid.
func CheckStatus(ctx context.Context, cfg Config) (Status, error) {
	if err := validateServerURL(cfg.ServerURL); err != nil {
		return Status{}, err
	}

	httpClient, err := newHTTPClient(cfg)
	if err != nil {
		return Status{}, err
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.ServerURL+"/api/v1/status", nil)
	if err != nil {
		return Status{}, fmt.Errorf("build status request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return classifyError(err), nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Status{
			State:  StateServerUnavailable,
			Detail: fmt.Sprintf("instance answered HTTP %d", resp.StatusCode),
		}, nil
	}

	var body statusBody
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil || body.Status != "ok" {
		return Status{
			State:  StateServerUnavailable,
			Detail: "instance returned a malformed status body",
		}, nil
	}

	return Status{
		State:         StateHealthy,
		Version:       body.Version,
		SchemaVersion: body.SchemaVersion,
	}, nil
}

// validateServerURL enforces the TLS rule from ADR 0004: plaintext HTTP is
// accepted only for loopback addresses.
func validateServerURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("parse server URL: %w", err)
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" && isLocalhost(u.Hostname()) {
		return nil
	}
	return fmt.Errorf("refusing insecure %q scheme for %s: HTTPS is required outside localhost", u.Scheme, u.Hostname())
}

func isLocalhost(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.IsLoopback()
	}
	return false
}

// newHTTPClient builds a client with system roots plus the optional
// deployment CA. Verification is never disabled.
func newHTTPClient(cfg Config) (*http.Client, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if cfg.CACertFile != "" {
		pemBytes, err := os.ReadFile(cfg.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("read CA certificate: %w", err)
		}
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("CA certificate %s contains no valid PEM blocks", cfg.CACertFile)
		}
	}
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}, nil
}

// classifyError maps transport failures onto the public taxonomy.
func classifyError(err error) Status {
	var unknownAuthority x509.UnknownAuthorityError
	var hostnameErr x509.HostnameError
	var certInvalid x509.CertificateInvalidError
	var recordErr tls.RecordHeaderError
	var dnsErr *net.DNSError
	var operationErr *net.OpError

	switch {
	case errors.As(err, &unknownAuthority),
		errors.As(err, &hostnameErr),
		errors.As(err, &certInvalid),
		errors.As(err, &recordErr):
		return Status{
			State:  StateTLSError,
			Detail: "TLS validation failed — treat this as a security error, not as offline mode",
		}
	case errors.As(err, &dnsErr):
		return Status{
			State:  StateClientOffline,
			Detail: "name resolution failed: " + dnsErr.Err,
		}
	case errors.As(err, &operationErr) &&
		(errors.Is(operationErr, syscall.ENETUNREACH) ||
			errors.Is(operationErr, syscall.EHOSTUNREACH) ||
			errors.Is(operationErr, syscall.ENETDOWN)):
		return Status{
			State:  StateClientOffline,
			Detail: "local network is unavailable: " + operationErr.Error(),
		}
	case errors.Is(err, context.DeadlineExceeded) || os.IsTimeout(err):
		return Status{
			State:  StateConnectionUnavailable,
			Detail: "connection timed out",
		}
	default:
		return Status{State: StateConnectionUnavailable, Detail: err.Error()}
	}
}
