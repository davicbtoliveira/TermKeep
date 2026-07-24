// Package blackbox is the primary TermKeep test seam: it boots the real
// reference stack (Traefik, server, PostgreSQL) with throwaway names and
// drives the compiled termkeep binary, asserting only observable behavior.
//
// Run with: go test ./test/blackbox/ -timeout 15m
// Skip with: go test -short ./...
package blackbox

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/creack/pty"
	"github.com/davicbtoliveira/TermKeep/internal/server"
)

// stack holds everything a test needs to reach the ephemeral deployment.
type stack struct {
	t          *testing.T
	project    string // docker compose project name
	repoRoot   string
	binary     string // compiled termkeep client
	certsDir   string // generated development CA and server certificate
	httpsPort  string // host port mapped to Traefik 443
	serverPort string // host port mapped to the server, loopback only
	serverURL  string
	env        []string // compose environment
}

func TestBlackbox(t *testing.T) {
	if testing.Short() {
		t.Skip("black-box tests require Docker; skipping in -short mode")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}

	s := newStack(t)

	t.Run("migrations applied on empty database", s.testMigrationsApplied)
	t.Run("status healthy through Traefik HTTPS", s.testStatusHealthy)
	t.Run("status reports TLS failure without CA", s.testStatusTLSFailure)
	t.Run("status reports unavailability when server is down", s.testStatusUnavailable)
	t.Run("proxy headers ignored from untrusted sources", s.testTrustedProxyEnforcement)
	t.Run("bare invocation opens TUI with instance state", s.testTUI)
	t.Run("bootstrap creates only encrypted administrator vault material", s.testBootstrap)
}

// newStack boots the ephemeral deployment once for the whole test run.
func newStack(t *testing.T) *stack {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	repoRoot := filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))

	s := &stack{
		t:          t,
		project:    fmt.Sprintf("termkeep-bb-%d", os.Getpid()),
		repoRoot:   repoRoot,
		httpsPort:  freePort(t),
		serverPort: freePort(t),
	}
	s.serverURL = "https://localhost:" + s.httpsPort

	// Development PKI: one CA signs the localhost server certificate. The
	// client test trusts the CA explicitly; verification stays enabled.
	s.certsDir = t.TempDir()
	run(t, repoRoot, nil, "bash", "deploy/generate-dev-certs.sh", s.certsDir)

	// Compile the client exactly as an operator would.
	s.binary = filepath.Join(t.TempDir(), "termkeep")
	run(t, repoRoot, nil, "go", "build", "-o", s.binary, "./cmd/termkeep")

	opaqueServerKey, oprfSeed, err := server.GenerateOPAQUEKeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	s.env = append(os.Environ(),
		"TERMKEEP_CERTS_DIR="+s.certsDir,
		"TERMKEEP_HTTPS_PORT="+s.httpsPort,
		"TERMKEEP_SERVER_PORT="+s.serverPort,
		"POSTGRES_PASSWORD=blackbox-postgres-password",
		"OPAQUE_SERVER_KEY="+opaqueServerKey,
		"OPAQUE_OPRF_SEED="+oprfSeed,
	)

	t.Cleanup(func() {
		cmd := s.composeCmd(context.Background(), "down", "-v", "--remove-orphans")
		_ = cmd.Run() // best effort; tests already reported their outcome
	})

	up := s.composeCmd(context.Background(), "up", "-d", "--build", "--wait")
	if out, err := up.CombinedOutput(); err != nil {
		t.Fatalf("compose up: %v\n%s", err, out)
	}

	s.waitHealthy(2 * time.Minute)
	return s
}

// waitHealthy polls the compiled client until the stack reports healthy.
func (s *stack) waitHealthy(deadline time.Duration) {
	s.t.Helper()
	stop := time.Now().Add(deadline)
	for {
		stdout, _, code := s.runClient("status")
		if code == 0 {
			s.t.Logf("stack healthy:\n%s", stdout)
			return
		}
		if time.Now().After(stop) {
			s.dumpLogs()
			s.t.Fatalf("stack did not become healthy within %s", deadline)
		}
		time.Sleep(2 * time.Second)
	}
}

// runClient executes the compiled termkeep binary with the shared config.
func (s *stack) runClient(args ...string) (stdout, stderr string, code int) {
	s.t.Helper()
	full := append([]string{
		"--server", s.serverURL,
		"--ca-cert", filepath.Join(s.certsDir, "ca.pem"),
	}, args...)
	cmd := exec.Command(s.binary, full...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &outBuf, &errBuf
	err := cmd.Run()
	return outBuf.String(), errBuf.String(), exitCode(err)
}

func (s *stack) composeCmd(ctx context.Context, args ...string) *exec.Cmd {
	full := append([]string{
		"compose",
		"-f", filepath.Join(s.repoRoot, "deploy", "compose.yml"),
		"-p", s.project,
	}, args...)
	cmd := exec.CommandContext(ctx, "docker", full...)
	cmd.Dir = s.repoRoot
	cmd.Env = s.env
	return cmd
}

// testMigrationsApplied proves booting the stack migrated the empty
// database: the bookkeeping table and the initial schema both exist.
func (s *stack) testMigrationsApplied(t *testing.T) {
	cmd := s.composeCmd(context.Background(),
		"exec", "-T", "db", "psql", "-U", "termkeep", "-d", "termkeep", "-tAc",
		"SELECT max(version) FROM schema_migrations")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("query schema_migrations: %v\n%s", err, out)
	}
	if strings.TrimSpace(string(out)) != "3" {
		t.Errorf("schema version: want 3, got %q", strings.TrimSpace(string(out)))
	}

	cmd = s.composeCmd(context.Background(),
		"exec", "-T", "db", "psql", "-U", "termkeep", "-d", "termkeep", "-tAc",
		"SELECT to_regclass('public.accounts')")
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("query accounts table: %v\n%s", err, out)
	}
	if strings.TrimSpace(string(out)) != "accounts" {
		t.Errorf("accounts table missing: %q", strings.TrimSpace(string(out)))
	}
}

// testStatusHealthy drives the compiled binary against the Traefik HTTPS
// endpoint with the development CA trusted.
func (s *stack) testStatusHealthy(t *testing.T) {
	stdout, stderr, code := s.runClient("status")
	if code != 0 {
		t.Fatalf("exit code: want 0, got %d (stderr: %s)", code, stderr)
	}
	if !strings.Contains(stdout, "Status:   healthy") {
		t.Errorf("stdout missing healthy state:\n%s", stdout)
	}
	if !strings.Contains(stdout, "schema v3") {
		t.Errorf("stdout missing schema version:\n%s", stdout)
	}
}

// testStatusTLSFailure omits the CA: validation must fail loudly, exit 2,
// and the wording must frame it as a security error.
func (s *stack) testStatusTLSFailure(t *testing.T) {
	cmd := exec.Command(s.binary, "--server", s.serverURL, "status")
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &outBuf, &errBuf
	err := cmd.Run()
	if code := exitCode(err); code != 2 {
		t.Fatalf("exit code: want 2, got %d", code)
	}
	if !strings.Contains(outBuf.String(), "TLS validation failed") {
		t.Errorf("stdout missing TLS failure:\n%s", outBuf.String())
	}
}

// testStatusUnavailable stops the server container: Traefik keeps
// listening, so the client sees a reachable but unhealthy instance.
func (s *stack) testStatusUnavailable(t *testing.T) {
	if out, err := s.composeCmd(context.Background(), "stop", "server").CombinedOutput(); err != nil {
		t.Fatalf("stop server: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		// Restore the stack for later subtests and wait until the server
		// is actually answering again.
		_ = s.composeCmd(context.Background(), "start", "server").Run()
		s.waitHealthy(time.Minute)
	})

	// Wait for Traefik to observe the missing backend before asserting.
	deadline := time.Now().Add(30 * time.Second)
	for {
		_, _, code := s.runClient("status")
		if code == 1 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("exit code never became 1 while server was down")
		}
		time.Sleep(time.Second)
	}
}

// testTrustedProxyEnforcement forges X-Forwarded-For from two origins:
// directly against the server (untrusted) and through Traefik (trusted).
// Neither may surface the forged address as the client IP.
func (s *stack) testTrustedProxyEnforcement(t *testing.T) {
	const forged = "203.0.113.99"

	direct := s.getStatusJSON(t, "http://localhost:"+s.serverPort, forged)
	if direct.ClientIP == forged {
		t.Errorf("direct request honored forged header: %+v", direct)
	}
	// The observed address is the Docker bridge gateway, not the forgery.
	if _, err := netip.ParseAddr(direct.ClientIP); err != nil {
		t.Errorf("direct client_ip %q is not an IP", direct.ClientIP)
	}

	viaProxy := s.getStatusJSON(t, s.serverURL, forged)
	if viaProxy.ClientIP == forged {
		t.Errorf("proxied request honored forged header: %+v", viaProxy)
	}
}

// getStatusJSON calls the status endpoint with a forged X-Forwarded-For
// header and decodes the public body.
func (s *stack) getStatusJSON(t *testing.T, baseURL, xff string) statusBody {
	t.Helper()
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfigWithCA(t, filepath.Join(s.certsDir, "ca.pem")),
		},
	}
	req, err := http.NewRequest(http.MethodGet, baseURL+"/api/v1/status", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Forwarded-For", xff)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", baseURL, err)
	}
	defer resp.Body.Close()
	var body statusBody
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode status body: %v", err)
	}
	return body
}

type statusBody struct {
	Status   string `json:"status"`
	ClientIP string `json:"client_ip"`
}

// testTUI runs the bare binary on a pseudo-terminal and asserts the TUI
// renders the same instance state as the status command.
func (s *stack) testTUI(t *testing.T) {
	cmd := exec.Command(s.binary)
	// Drop any inherited TERM first: a duplicated variable would shadow
	// the override (getenv returns the first occurrence).
	cmd.Env = withoutEnv(os.Environ(), "TERM", "TERMKEEP_SERVER", "TERMKEEP_CA_CERT")
	cmd.Env = append(cmd.Env,
		"TERMKEEP_SERVER="+s.serverURL,
		"TERMKEEP_CA_CERT="+filepath.Join(s.certsDir, "ca.pem"),
		// TERM=dumb: Bubble Tea skips terminal capability queries (OSC 11,
		// DSR) that a pseudo-terminal would never answer.
		"TERM=dumb",
	)

	// A zero-sized terminal renders nothing; give the TUI real geometry.
	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: 24, Cols: 80})
	if err != nil {
		t.Fatalf("start pty: %v", err)
	}
	defer func() { _ = ptmx.Close() }()

	var mu sync.Mutex
	var buf bytes.Buffer
	go func() { _, _ = io.Copy(&lockedWriter{&mu, &buf}, ptmx) }()

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		plain := stripANSI(buf.String())
		mu.Unlock()
		if strings.Contains(plain, "Status:   healthy") {
			write(t, ptmx, "q")
			waitExit(t, cmd)
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("TUI did not render a healthy instance state in time; got:\n%s", stripANSI(buf.String()))
}

// testBootstrap drives the compiled CLI through a real terminal, then checks
// PostgreSQL and server logs for a known plaintext fixture. It proves the
// first account is an administrator, repeated registration is closed, and
// neither encrypted persistence nor observability contains the password.
func (s *stack) testBootstrap(t *testing.T) {
	const (
		email    = "admin@example.com"
		password = "TermKeep#2026"
	)

	output, code := s.runBootstrap(t, email, password)
	if code != 0 {
		t.Fatalf("bootstrap exit code: want 0, got %d\n%s", code, output)
	}
	if !strings.Contains(output, "Recovery key — save it now") {
		t.Fatalf("bootstrap did not warn about one-time recovery key:\n%s", output)
	}
	if !strings.Contains(output, "Vault:    unlocked (empty)") {
		t.Fatalf("bootstrap did not open empty vault:\n%s", output)
	}

	cmd := s.composeCmd(context.Background(),
		"exec", "-T", "db", "psql", "-U", "termkeep", "-d", "termkeep", "-tAc", `
			SELECT a.email || ':' || a.is_administrator || ':' ||
				(position(convert_to('TermKeep#2026', 'UTF8') in r.record) = 0 AND
				 position(convert_to('TermKeep#2026', 'UTF8') in v.password_vault_envelope) = 0 AND
				 position(convert_to('TermKeep#2026', 'UTF8') in v.recovery_vault_envelope) = 0)
			FROM accounts a
			JOIN opaque_records r ON r.account_uuid = a.uuid
			JOIN vault_envelopes v ON v.account_uuid = a.uuid`)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("query bootstrap persistence: %v\n%s", err, out)
	}
	if strings.TrimSpace(string(out)) != "admin@example.com:true:true" {
		t.Fatalf("unexpected bootstrap persistence: %q", strings.TrimSpace(string(out)))
	}

	logs, err := s.composeCmd(context.Background(), "logs", "server").CombinedOutput()
	if err != nil {
		t.Fatalf("read server logs: %v\n%s", err, logs)
	}
	if bytes.Contains(logs, []byte(password)) {
		t.Fatal("server logs contain master password fixture")
	}

	_, retryCode := s.runBootstrap(t, "another@example.com", password)
	if retryCode == 0 {
		t.Fatal("second bootstrap unexpectedly succeeded")
	}
}

func (s *stack) runBootstrap(t *testing.T, email, password string) (string, int) {
	t.Helper()
	cmd := exec.Command(s.binary,
		"--server", s.serverURL,
		"--ca-cert", filepath.Join(s.certsDir, "ca.pem"),
		"bootstrap", "--email", email)
	cmd.Env = withoutEnv(os.Environ(), "TERM", "TERMKEEP_SERVER", "TERMKEEP_CA_CERT")
	cmd.Env = append(cmd.Env, "TERM=dumb")

	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: 24, Cols: 80})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ptmx.Close() }()

	var mu sync.Mutex
	var buf bytes.Buffer
	go func() { _, _ = io.Copy(&lockedWriter{&mu, &buf}, ptmx) }()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	stage := 0
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			mu.Lock()
			output := stripANSI(buf.String())
			mu.Unlock()
			return output, exitCode(err)
		default:
		}
		mu.Lock()
		plain := stripANSI(buf.String())
		mu.Unlock()
		switch stage {
		case 0:
			if strings.Contains(plain, "Master password:") {
				write(t, ptmx, password+"\n")
				stage++
			}
		case 1:
			if strings.Contains(plain, "Confirm master password:") {
				write(t, ptmx, password+"\n")
				stage++
			}
		case 2:
			if strings.Contains(plain, "Vault:    unlocked (empty)") {
				write(t, ptmx, "q")
				stage++
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	mu.Lock()
	output := stripANSI(buf.String())
	mu.Unlock()
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	return output, -1
}

// lockedWriter serializes PTY reads with test-side inspection.
type lockedWriter struct {
	mu  *sync.Mutex
	buf *bytes.Buffer
}

func (w *lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

// waitExit asserts the TUI exits cleanly after the quit key.
func waitExit(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("termkeep exited with error: %v", err)
		}
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("termkeep did not exit after 'q'")
	}
}

func (s *stack) dumpLogs() {
	out, err := s.composeCmd(context.Background(), "logs", "--tail", "50").CombinedOutput()
	if err == nil {
		s.t.Logf("compose logs:\n%s", out)
	}
}

// freePort reserves and releases an ephemeral loopback port.
func freePort(t *testing.T) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lis.Close()
	_, port, err := net.SplitHostPort(lis.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return port
}

func run(t *testing.T, dir string, env []string, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = env
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}

// tlsConfigWithCA builds TLS settings trusting the development CA. The
// black-box stack uses a self-signed chain; verification stays enabled.
func tlsConfigWithCA(t *testing.T, caFile string) *tls.Config {
	t.Helper()
	pemBytes, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		t.Fatalf("no PEM blocks in %s", caFile)
	}
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
}

// withoutEnv returns the environment with the named variables removed.
func withoutEnv(env []string, names ...string) []string {
	out := env[:0]
	for _, e := range env {
		keep := true
		for _, n := range names {
			if strings.HasPrefix(e, n+"=") {
				keep = false
				break
			}
		}
		if keep {
			out = append(out, e)
		}
	}
	return out
}

func write(t *testing.T, w io.Writer, s string) {
	t.Helper()
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatalf("write to pty: %v", err)
	}
}

// stripANSI removes escape sequences so assertions see plain text.
func stripANSI(s string) string {
	var b strings.Builder
	inEscape := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == 0x1b:
			inEscape = true
		case inEscape && (c == 'm' || c == 'K' || c == 'J' || c == 'H'):
			inEscape = false
		case !inEscape:
			b.WriteByte(c)
		}
	}
	return b.String()
}
