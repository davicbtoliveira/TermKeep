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
	"encoding/base64"
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
	"syscall"
	"testing"
	"time"

	"github.com/bytemare/opaque"
	"github.com/creack/pty"
	"github.com/davicbtoliveira/TermKeep/internal/client"
	"github.com/davicbtoliveira/TermKeep/internal/server"
	"github.com/davicbtoliveira/TermKeep/internal/session"
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
	t.Run("login reuses unlocked session in the same terminal", s.testTerminalSessionReuse)
	t.Run("another terminal requires its own login", s.testTerminalSessionIsolation)
	t.Run("logout clears the terminal session", s.testTerminalSessionLogout)
	t.Run("terminal session socket is owner-only", s.testTerminalSessionSocketPermissions)
	t.Run("ending the shell clears the terminal session", s.testTerminalSessionOwnerExit)
	t.Run("Active Sessions shows online session metadata", s.testActiveSessionsScreen)
	t.Run("Active Sessions revokes a remote session", s.testActiveSessionsRevoke)
	t.Run("invited user registers an isolated vault", s.testInvitedRegistration)
	t.Run("Activity separates user and administrator views", s.testActivityViews)
	t.Run("audit persistence and logs exclude secrets", s.testAuditExcludesSecrets)
	t.Run("expired invitation cannot register", s.testExpiredInvitation)
	t.Run("concurrent invitation consumption registers once", s.testConcurrentInvitationConsumption)
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
	if strings.TrimSpace(string(out)) != "5" {
		t.Errorf("schema version: want 5, got %q", strings.TrimSpace(string(out)))
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
	if !strings.Contains(stdout, "schema v5") {
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

func (s *stack) testTerminalSessionReuse(t *testing.T) {
	const (
		email    = "admin@example.com"
		password = "TermKeep#2026"
	)
	shell := s.startTerminalShell(t)
	command := fmt.Sprintf("%q --server %q --ca-cert %q login --email %q\n",
		s.binary, s.serverURL, filepath.Join(s.certsDir, "ca.pem"), email)
	shell.login(command, password)

	shell.clear()
	write(t, shell.ptmx, command)
	matched, output := shell.waitFor(30*time.Second, "Master password:", "Vault:    unlocked (empty)")
	if matched == "Master password:" {
		t.Fatalf("same terminal requested master password again:\n%s", output)
	}
	if matched != "Vault:    unlocked (empty)" {
		t.Fatalf("same terminal did not reuse unlocked session:\n%s", output)
	}
	write(t, shell.ptmx, "q")
	shell.waitFor(10*time.Second, terminalShellPrompt)
}

func (s *stack) testTerminalSessionIsolation(t *testing.T) {
	const (
		email    = "admin@example.com"
		password = "TermKeep#2026"
	)
	command := fmt.Sprintf("%q --server %q --ca-cert %q login --email %q\n",
		s.binary, s.serverURL, filepath.Join(s.certsDir, "ca.pem"), email)
	owner := s.startTerminalShell(t)
	owner.login(command, password)

	other := s.startTerminalShell(t)
	other.clear()
	write(t, other.ptmx, command)
	matched, output := other.waitFor(30*time.Second, "Master password:", "Vault:    unlocked (empty)")
	if matched != "Master password:" {
		t.Fatalf("other terminal reused unlocked session:\n%s", output)
	}
}

func (s *stack) testTerminalSessionLogout(t *testing.T) {
	const (
		email    = "admin@example.com"
		password = "TermKeep#2026"
	)
	loginCommand := fmt.Sprintf("%q --server %q --ca-cert %q login --email %q\n",
		s.binary, s.serverURL, filepath.Join(s.certsDir, "ca.pem"), email)
	shell := s.startTerminalShell(t)
	shell.login(loginCommand, password)

	shell.clear()
	write(t, shell.ptmx, fmt.Sprintf("%q logout\n", s.binary))
	if _, output := shell.waitFor(10*time.Second, "Session: locked"); !strings.Contains(output, "Session: locked") {
		t.Fatalf("logout did not report locked session:\n%s", output)
	}
	shell.waitFor(10*time.Second, terminalShellPrompt)

	shell.clear()
	write(t, shell.ptmx, loginCommand)
	matched, output := shell.waitFor(30*time.Second, "Master password:", "Vault:    unlocked (empty)")
	if matched != "Master password:" {
		t.Fatalf("login remained unlocked after logout:\n%s", output)
	}
}

func (s *stack) testTerminalSessionOwnerExit(t *testing.T) {
	const (
		email    = "admin@example.com"
		password = "TermKeep#2026"
	)
	loginCommand := fmt.Sprintf("%q --server %q --ca-cert %q login --email %q\n",
		s.binary, s.serverURL, filepath.Join(s.certsDir, "ca.pem"), email)
	shell := s.startTerminalShell(t)
	shell.login(loginCommand, password)

	sockets, err := filepath.Glob(filepath.Join(shell.runtimeDir, "termkeep", "*.sock"))
	if err != nil {
		t.Fatal(err)
	}
	if len(sockets) != 1 {
		t.Fatalf("session sockets: want 1, got %d", len(sockets))
	}
	token, err := session.AccessToken(context.Background(), sockets[0])
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for index := range token {
			token[index] = 0
		}
	}()
	write(t, shell.ptmx, "exit\n")
	shell.waitExit(5 * time.Second)

	deadline := time.Now().Add(2 * time.Second)
	socketRemoved := false
	for time.Now().Before(deadline) {
		if _, err := os.Stat(sockets[0]); os.IsNotExist(err) {
			socketRemoved = true
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !socketRemoved {
		t.Fatal("session socket remained after owner shell exited")
	}
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := client.ListSessions(context.Background(), s.clientConfig(), string(token)); err != nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("online session remained authorized after owner shell exited")
}

func (s *stack) testTerminalSessionSocketPermissions(t *testing.T) {
	const (
		email    = "admin@example.com"
		password = "TermKeep#2026"
	)
	loginCommand := fmt.Sprintf("%q --server %q --ca-cert %q login --email %q\n",
		s.binary, s.serverURL, filepath.Join(s.certsDir, "ca.pem"), email)
	shell := s.startTerminalShell(t)
	shell.login(loginCommand, password)

	runtimeDir := filepath.Join(shell.runtimeDir, "termkeep")
	runtimeInfo, err := os.Stat(runtimeDir)
	if err != nil {
		t.Fatal(err)
	}
	if got := runtimeInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("session runtime directory mode: want 0700, got %04o", got)
	}
	sockets, err := filepath.Glob(filepath.Join(runtimeDir, "*.sock"))
	if err != nil {
		t.Fatal(err)
	}
	if len(sockets) != 1 {
		t.Fatalf("session sockets: want 1, got %d", len(sockets))
	}
	socketInfo, err := os.Stat(sockets[0])
	if err != nil {
		t.Fatal(err)
	}
	if got := socketInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("session socket mode: want 0600, got %04o", got)
	}
	stat, ok := socketInfo.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) {
		t.Fatalf("session socket is not owned by UID %d", os.Getuid())
	}
}

func (s *stack) testActiveSessionsScreen(t *testing.T) {
	const (
		email    = "admin@example.com"
		password = "TermKeep#2026"
	)
	remote, err := client.Login(context.Background(), s.clientConfig(), client.LoginInput{
		Email:          email,
		MasterPassword: password,
		Host:           "remote-host",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Clear()
	t.Cleanup(func() {
		_ = client.RevokeSession(context.Background(), s.clientConfig(), remote.AccessToken, "current")
	})

	loginCommand := fmt.Sprintf("%q --server %q --ca-cert %q login --email %q\n",
		s.binary, s.serverURL, filepath.Join(s.certsDir, "ca.pem"), email)
	shell := s.startTerminalShell(t)
	shell.clear()
	write(t, shell.ptmx, loginCommand)
	if matched, output := shell.waitFor(30*time.Second, "Master password:"); matched == "" {
		t.Fatalf("login did not request master password:\n%s", output)
	}
	write(t, shell.ptmx, password+"\n")
	shell.waitFor(45*time.Second, "Vault:    unlocked (empty)")

	shell.clear()
	write(t, shell.ptmx, "s")
	_, output := shell.waitFor(30*time.Second, "remote-host")
	for _, want := range []string{"Active Sessions", "IP:", "Created:", "Last use:"} {
		if !strings.Contains(output, want) {
			t.Fatalf("Active Sessions missing %q:\n%s", want, output)
		}
	}
	write(t, shell.ptmx, "q")
	shell.waitFor(10*time.Second, terminalShellPrompt)
}

func (s *stack) testActiveSessionsRevoke(t *testing.T) {
	const (
		email    = "admin@example.com"
		password = "TermKeep#2026"
	)
	remote, err := client.Login(context.Background(), s.clientConfig(), client.LoginInput{
		Email:          email,
		MasterPassword: password,
		Host:           "remote-to-revoke",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Clear()

	loginCommand := fmt.Sprintf("%q --server %q --ca-cert %q login --email %q\n",
		s.binary, s.serverURL, filepath.Join(s.certsDir, "ca.pem"), email)
	shell := s.startTerminalShell(t)
	shell.clear()
	write(t, shell.ptmx, loginCommand)
	shell.waitFor(30*time.Second, "Master password:")
	write(t, shell.ptmx, password+"\n")
	shell.waitFor(45*time.Second, "Vault:    unlocked (empty)")
	write(t, shell.ptmx, "s")
	shell.waitFor(30*time.Second, "remote-to-revoke")
	shell.clear()
	write(t, shell.ptmx, "j")
	shell.waitFor(10*time.Second, "> remote-to-revoke")
	write(t, shell.ptmx, "x")

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := client.ListSessions(context.Background(), s.clientConfig(), remote.AccessToken); err != nil {
			write(t, shell.ptmx, "q")
			shell.waitFor(10*time.Second, terminalShellPrompt)
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("revoked remote token remained authorized")
}

func (s *stack) testInvitedRegistration(t *testing.T) {
	const (
		adminEmail    = "admin@example.com"
		adminPassword = "TermKeep#2026"
		userEmail     = "friend@example.com"
		userPassword  = "Friend#Pass2026"
	)

	admin, err := client.Login(context.Background(), s.clientConfig(), client.LoginInput{
		Email:          adminEmail,
		MasterPassword: adminPassword,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Clear()
	invite := s.createInvite(t, admin.AccessToken, userEmail)

	output, code := s.runRegistration(t, userEmail, userPassword, invite.Token)
	if code != 0 {
		t.Fatalf("registration exit code: want 0, got %d\n%s", code, output)
	}
	if !strings.Contains(output, "Recovery key — save it now") {
		t.Fatalf("registration did not warn about one-time recovery key:\n%s", output)
	}
	if !strings.Contains(output, "Vault:    unlocked (empty)") {
		t.Fatalf("registration did not open empty vault:\n%s", output)
	}

	user, err := client.Login(context.Background(), s.clientConfig(), client.LoginInput{
		Email:          userEmail,
		MasterPassword: userPassword,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer user.Clear()
	if admin.AccountID == user.AccountID {
		t.Fatal("administrator and invited user share an account UUID")
	}
	if bytes.Equal(admin.VaultKey, user.VaultKey) {
		t.Fatal("administrator and invited user share a vault key")
	}

	reused, err := client.Register(context.Background(), s.clientConfig(), client.RegisterInput{
		Email:                 userEmail,
		InviteToken:           invite.Token,
		MasterPassword:        "Another#Pass2026",
		ConfirmMasterPassword: "Another#Pass2026",
	})
	if err == nil {
		reused.Vault.Clear()
		t.Fatal("consumed invitation registered a second account")
	}

	httpClient := &http.Client{Transport: &http.Transport{
		TLSClientConfig: tlsConfigWithCA(t, filepath.Join(s.certsDir, "ca.pem")),
	}}
	request, err := http.NewRequest(http.MethodGet, s.serverURL+"/api/v1/accounts", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+admin.AccessToken)
	response, err := httpClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		t.Fatalf("list accounts status: want 200, got %d", response.StatusCode)
	}
	var accountList struct {
		Accounts []map[string]any `json:"accounts"`
	}
	if err := json.NewDecoder(response.Body).Decode(&accountList); err != nil {
		response.Body.Close()
		t.Fatal(err)
	}
	response.Body.Close()
	if len(accountList.Accounts) != 2 {
		t.Fatalf("account list length: want 2, got %d", len(accountList.Accounts))
	}
	for _, account := range accountList.Accounts {
		if len(account) != 3 {
			t.Fatalf("account list exposed unexpected metadata: %#v", account)
		}
		for _, field := range []string{"uuid", "email", "status"} {
			if account[field] == nil || account[field] == "" {
				t.Fatalf("account list missing %s: %#v", field, account)
			}
		}
	}

	request, err = http.NewRequest(http.MethodGet, s.serverURL+"/api/v1/accounts", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+user.AccessToken)
	response, err = httpClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("non-administrator account list status: want 401, got %d", response.StatusCode)
	}
}

func (s *stack) testActivityViews(t *testing.T) {
	const (
		adminEmail    = "admin@example.com"
		adminPassword = "TermKeep#2026"
		userEmail     = "friend@example.com"
		userPassword  = "Friend#Pass2026"
	)
	admin, err := client.Login(context.Background(), s.clientConfig(), client.LoginInput{
		Email:          adminEmail,
		MasterPassword: adminPassword,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Clear()
	user, err := client.Login(context.Background(), s.clientConfig(), client.LoginInput{
		Email:          userEmail,
		MasterPassword: userPassword,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer user.Clear()

	own, err := client.ListActivity(
		context.Background(), s.clientConfig(), user.AccessToken, false, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(own.Events) == 0 || own.CanViewAll {
		t.Fatalf("ordinary account activity metadata: %+v", own)
	}
	for _, event := range own.Events {
		if event.AccountID != user.AccountID {
			t.Fatalf("ordinary account read cross-account event: %+v", event)
		}
	}
	if _, err := client.ListActivity(
		context.Background(), s.clientConfig(), user.AccessToken, true, ""); err == nil {
		t.Fatal("ordinary account read administrative activity")
	}

	all, err := client.ListActivity(
		context.Background(), s.clientConfig(), admin.AccessToken, true, "")
	if err != nil {
		t.Fatal(err)
	}
	var sawUserRegistration, sawAdminActor bool
	for _, event := range all.Events {
		if event.Type == "registration.succeeded" &&
			event.AccountID == user.AccountID &&
			event.ActorID == user.AccountID {
			sawUserRegistration = true
		}
		if event.ActorID == admin.AccountID {
			sawAdminActor = true
		}
	}
	if !all.CanViewAll || !sawUserRegistration || !sawAdminActor {
		t.Fatalf("administrator activity incomplete: %+v", all)
	}

	loginCommand := fmt.Sprintf("%q --server %q --ca-cert %q login --email %q\n",
		s.binary, s.serverURL, filepath.Join(s.certsDir, "ca.pem"), userEmail)
	userShell := s.startTerminalShell(t)
	userShell.clear()
	write(t, userShell.ptmx, loginCommand)
	userShell.waitFor(30*time.Second, "Master password:")
	write(t, userShell.ptmx, userPassword+"\n")
	userShell.waitFor(45*time.Second, "Vault:    unlocked (empty)")
	userShell.clear()
	write(t, userShell.ptmx, "a")
	_, output := userShell.waitFor(30*time.Second, "login.succeeded")
	for _, want := range []string{"Activity", "my account", "Actor:", "Source:"} {
		if !strings.Contains(output, want) {
			t.Fatalf("user Activity missing %q:\n%s", want, output)
		}
	}
	if strings.Contains(output, "[g] all accounts") {
		t.Fatalf("ordinary account Activity exposed global control:\n%s", output)
	}
	write(t, userShell.ptmx, "q")
	userShell.waitFor(10*time.Second, terminalShellPrompt)

	adminCommand := fmt.Sprintf("%q --server %q --ca-cert %q login --email %q\n",
		s.binary, s.serverURL, filepath.Join(s.certsDir, "ca.pem"), adminEmail)
	adminShell := s.startTerminalShell(t)
	adminShell.clear()
	write(t, adminShell.ptmx, adminCommand)
	adminShell.waitFor(30*time.Second, "Master password:")
	write(t, adminShell.ptmx, adminPassword+"\n")
	adminShell.waitFor(45*time.Second, "Vault:    unlocked (empty)")
	adminShell.clear()
	write(t, adminShell.ptmx, "a")
	adminShell.waitFor(30*time.Second, "[g] all accounts")
	adminShell.clear()
	write(t, adminShell.ptmx, "g")
	_, output = adminShell.waitFor(30*time.Second, "all accounts")
	for _, want := range []string{"Account:", "Actor:"} {
		if !strings.Contains(output, want) {
			t.Fatalf("administrator Activity missing %q:\n%s", want, output)
		}
	}
	write(t, adminShell.ptmx, "q")
	adminShell.waitFor(10*time.Second, terminalShellPrompt)
}

func (s *stack) testAuditExcludesSecrets(t *testing.T) {
	const (
		adminEmail    = "admin@example.com"
		adminPassword = "TermKeep#2026"
	)
	admin, err := client.Login(context.Background(), s.clientConfig(), client.LoginInput{
		Email:          adminEmail,
		MasterPassword: adminPassword,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Clear()
	invite := s.createInvite(t, admin.AccessToken, "audit-probe@example.com")

	forbiddenInput := map[string]string{
		"email":           "another@example.com",
		"master_password": "Master-Field-Sentinel",
		"recovery_key":    "Recovery-Key-Sentinel",
		"item_content":    "Item-Content-Sentinel",
		"search_term":     "Search-Term-Sentinel",
		"totp":            "TOTP-Sentinel",
	}
	payload, err := json.Marshal(forbiddenInput)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(
		http.MethodPost, s.serverURL+"/api/v1/invites", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+admin.AccessToken)
	request.Header.Set("Content-Type", "application/json")
	httpClient := &http.Client{Transport: &http.Transport{
		TLSClientConfig: tlsConfigWithCA(t, filepath.Join(s.certsDir, "ca.pem")),
	}}
	response, err := httpClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("secret-bearing unknown fields: want 400, got %d", response.StatusCode)
	}

	activity, err := client.ListActivity(
		context.Background(), s.clientConfig(), admin.AccessToken, true, "")
	if err != nil {
		t.Fatal(err)
	}
	apiBody, err := json.Marshal(activity)
	if err != nil {
		t.Fatal(err)
	}
	dbCommand := s.composeCmd(context.Background(),
		"exec", "-T", "db", "psql", "-U", "termkeep", "-d", "termkeep", "-tAc",
		"SELECT COALESCE(string_agg(row_to_json(a)::text, E'\\n'), '') FROM audit_events a")
	dbBody, err := dbCommand.CombinedOutput()
	if err != nil {
		t.Fatalf("read audit events: %v\n%s", err, dbBody)
	}
	logBody, err := s.composeCmd(context.Background(), "logs", "server").CombinedOutput()
	if err != nil {
		t.Fatalf("read server logs: %v\n%s", err, logBody)
	}
	surfaces := map[string][]byte{
		"API":        apiBody,
		"PostgreSQL": dbBody,
		"logs":       logBody,
	}
	for _, secret := range []string{
		adminPassword,
		admin.AccessToken,
		invite.Token,
		"Master-Field-Sentinel",
		"Recovery-Key-Sentinel",
		"Item-Content-Sentinel",
		"Search-Term-Sentinel",
		"TOTP-Sentinel",
	} {
		for surface, contents := range surfaces {
			if bytes.Contains(contents, []byte(secret)) {
				t.Fatalf("%s contains forbidden secret %q", surface, secret)
			}
		}
	}
}

func (s *stack) testExpiredInvitation(t *testing.T) {
	const (
		adminEmail    = "admin@example.com"
		adminPassword = "TermKeep#2026"
		userEmail     = "expired@example.com"
	)
	admin, err := client.Login(context.Background(), s.clientConfig(), client.LoginInput{
		Email:          adminEmail,
		MasterPassword: adminPassword,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Clear()
	invite := s.createInvite(t, admin.AccessToken, userEmail)

	cmd := s.composeCmd(context.Background(),
		"exec", "-T", "db", "psql", "-U", "termkeep", "-d", "termkeep", "-v", "ON_ERROR_STOP=1", "-c",
		"UPDATE invites SET expires_at = now() - interval '1 minute' WHERE uuid = '"+invite.InviteID+"'")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("expire invite: %v\n%s", err, out)
	}

	registered, err := client.Register(context.Background(), s.clientConfig(), client.RegisterInput{
		Email:                 userEmail,
		InviteToken:           invite.Token,
		MasterPassword:        "Expired#Pass2026",
		ConfirmMasterPassword: "Expired#Pass2026",
	})
	if err == nil {
		registered.Vault.Clear()
		t.Fatal("expired invitation registered an account")
	}
}

func (s *stack) testConcurrentInvitationConsumption(t *testing.T) {
	const (
		adminEmail    = "admin@example.com"
		adminPassword = "TermKeep#2026"
		userEmail     = "concurrent@example.com"
	)
	admin, err := client.Login(context.Background(), s.clientConfig(), client.LoginInput{
		Email:          adminEmail,
		MasterPassword: adminPassword,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Clear()
	invite := s.createInvite(t, admin.AccessToken, userEmail)

	password := []byte("Concurrent#Pass2026")
	first := s.prepareRegistration(t, userEmail, password, invite.Token)
	second := s.prepareRegistration(t, userEmail, password, invite.Token)
	httpClient := &http.Client{Transport: &http.Transport{
		TLSClientConfig: tlsConfigWithCA(t, filepath.Join(s.certsDir, "ca.pem")),
	}}

	start := make(chan struct{})
	statuses := make(chan int, 2)
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, body := range []map[string]string{first, second} {
		wg.Add(1)
		go func(body map[string]string) {
			defer wg.Done()
			<-start
			status, err := postJSONStatus(httpClient, s.serverURL+"/api/v1/register/finish", body)
			if err != nil {
				errs <- err
				return
			}
			statuses <- status
		}(body)
	}
	close(start)
	wg.Wait()
	close(statuses)
	close(errs)

	for err := range errs {
		t.Error(err)
	}
	var created, rejected int
	for status := range statuses {
		switch status {
		case http.StatusCreated:
			created++
		case http.StatusUnauthorized:
			rejected++
		default:
			t.Errorf("concurrent registration returned HTTP %d", status)
		}
	}
	if created != 1 || rejected != 1 {
		t.Fatalf("concurrent results: want one 201 and one 401, got %d and %d", created, rejected)
	}

	cmd := s.composeCmd(context.Background(),
		"exec", "-T", "db", "psql", "-U", "termkeep", "-d", "termkeep", "-tAc",
		"SELECT count(*) FROM accounts WHERE email = '"+userEmail+"'")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("count concurrent accounts: %v\n%s", err, out)
	}
	if strings.TrimSpace(string(out)) != "1" {
		t.Fatalf("concurrent account count: want 1, got %q", strings.TrimSpace(string(out)))
	}
}

func (s *stack) prepareRegistration(t *testing.T, email string, password []byte, inviteToken string) map[string]string {
	t.Helper()
	opaqueClient, err := opaque.NewClient(nil)
	if err != nil {
		t.Fatal(err)
	}
	request, err := opaqueClient.RegistrationInit(password)
	if err != nil {
		t.Fatal(err)
	}
	startResponse, err := postJSONResponse(
		&http.Client{Transport: &http.Transport{
			TLSClientConfig: tlsConfigWithCA(t, filepath.Join(s.certsDir, "ca.pem")),
		}},
		s.serverURL+"/api/v1/register/start",
		map[string]string{
			"email":                email,
			"invite_token":         inviteToken,
			"registration_request": base64.RawStdEncoding.EncodeToString(request.Serialize()),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer startResponse.Body.Close()
	if startResponse.StatusCode != http.StatusOK {
		t.Fatalf("registration start status: want 200, got %d", startResponse.StatusCode)
	}
	var startBody struct {
		AccountID            string `json:"account_id"`
		RegistrationResponse string `json:"registration_response"`
	}
	if err := json.NewDecoder(startResponse.Body).Decode(&startBody); err != nil {
		t.Fatal(err)
	}
	responseBytes, err := base64.RawStdEncoding.DecodeString(startBody.RegistrationResponse)
	if err != nil {
		t.Fatal(err)
	}
	response, err := opaqueClient.Deserialize.RegistrationResponse(responseBytes)
	if err != nil {
		t.Fatal(err)
	}
	record, _, err := opaqueClient.RegistrationFinalize(response, []byte(email), nil)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]string{
		"account_id":              startBody.AccountID,
		"email":                   email,
		"invite_token":            inviteToken,
		"registration_record":     base64.RawStdEncoding.EncodeToString(record.Serialize()),
		"password_vault_envelope": base64.RawStdEncoding.EncodeToString([]byte("concurrent-password-envelope")),
		"recovery_vault_envelope": base64.RawStdEncoding.EncodeToString([]byte("concurrent-recovery-envelope")),
	}
}

func postJSONResponse(httpClient *http.Client, url string, body any) (*http.Response, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	return httpClient.Do(request)
}

func postJSONStatus(httpClient *http.Client, url string, body any) (int, error) {
	response, err := postJSONResponse(httpClient, url, body)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	return response.StatusCode, nil
}

func (s *stack) clientConfig() client.Config {
	return client.Config{
		ServerURL:  s.serverURL,
		CACertFile: filepath.Join(s.certsDir, "ca.pem"),
	}
}

type inviteBody struct {
	InviteID string `json:"invite_id"`
	Token    string `json:"token"`
}

func (s *stack) createInvite(t *testing.T, accessToken, email string) inviteBody {
	t.Helper()
	payload, err := json.Marshal(map[string]string{"email": email})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, s.serverURL+"/api/v1/invites", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+accessToken)
	request.Header.Set("Content-Type", "application/json")
	httpClient := &http.Client{Transport: &http.Transport{
		TLSClientConfig: tlsConfigWithCA(t, filepath.Join(s.certsDir, "ca.pem")),
	}}
	response, err := httpClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("create invite status: want 201, got %d", response.StatusCode)
	}
	var body inviteBody
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Token == "" {
		t.Fatal("create invite response omitted token")
	}
	return body
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

func (s *stack) runRegistration(t *testing.T, email, password, inviteToken string) (string, int) {
	t.Helper()
	cmd := exec.Command(s.binary,
		"--server", s.serverURL,
		"--ca-cert", filepath.Join(s.certsDir, "ca.pem"),
		"register", "--email", email, "--invite-token", inviteToken)
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

const terminalShellPrompt = "termkeep-test> "

type terminalShell struct {
	t          *testing.T
	cmd        *exec.Cmd
	ptmx       *os.File
	runtimeDir string
	mu         sync.Mutex
	buf        bytes.Buffer
	waitErr    error
	done       chan struct{}
}

func (s *stack) startTerminalShell(t *testing.T) *terminalShell {
	t.Helper()
	cmd := exec.Command("sh")
	cmd.Env = withoutEnv(os.Environ(),
		"TERM", "PS1", "TERMKEEP_SERVER", "TERMKEEP_CA_CERT", "XDG_RUNTIME_DIR")
	runtimeDir, err := os.MkdirTemp("/tmp", "tk-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(runtimeDir) })
	cmd.Env = append(cmd.Env,
		"TERM=dumb",
		"PS1="+terminalShellPrompt,
		"XDG_RUNTIME_DIR="+runtimeDir,
	)
	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: 24, Cols: 80})
	if err != nil {
		t.Fatal(err)
	}
	shell := &terminalShell{
		t:          t,
		cmd:        cmd,
		ptmx:       ptmx,
		runtimeDir: runtimeDir,
		done:       make(chan struct{}),
	}
	go func() { _, _ = io.Copy(&lockedWriter{&shell.mu, &shell.buf}, ptmx) }()
	go func() {
		err := cmd.Wait()
		shell.mu.Lock()
		shell.waitErr = err
		shell.mu.Unlock()
		close(shell.done)
	}()
	t.Cleanup(func() {
		_ = ptmx.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		select {
		case <-shell.done:
		case <-time.After(5 * time.Second):
			t.Error("terminal shell did not exit")
		}
	})
	shell.waitFor(10*time.Second, terminalShellPrompt)
	return shell
}

func (s *terminalShell) clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buf.Reset()
}

func (s *terminalShell) login(command, password string) {
	s.t.Helper()
	s.clear()
	write(s.t, s.ptmx, command)
	if matched, output := s.waitFor(30*time.Second, "Master password:", "Vault:    unlocked (empty)"); matched != "Master password:" {
		s.t.Fatalf("first login did not request master password:\n%s", output)
	}
	write(s.t, s.ptmx, password+"\n")
	if _, output := s.waitFor(45*time.Second, "Vault:    unlocked (empty)"); !strings.Contains(output, "Vault:    unlocked (empty)") {
		s.t.Fatalf("login did not open vault:\n%s", output)
	}
	write(s.t, s.ptmx, "q")
	s.waitFor(10*time.Second, terminalShellPrompt)
}

func (s *terminalShell) waitFor(timeout time.Duration, values ...string) (string, string) {
	s.t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		output := stripANSI(s.buf.String())
		s.mu.Unlock()
		for _, value := range values {
			if strings.Contains(output, value) {
				return value, output
			}
		}
		select {
		case <-s.done:
			s.mu.Lock()
			err := s.waitErr
			s.mu.Unlock()
			s.t.Fatalf("terminal shell exited while waiting for %q: %v\n%s", values, err, output)
		default:
		}
		time.Sleep(25 * time.Millisecond)
	}
	s.mu.Lock()
	output := stripANSI(s.buf.String())
	s.mu.Unlock()
	s.t.Fatalf("terminal shell timed out waiting for %q:\n%s", values, output)
	return "", output
}

func (s *terminalShell) waitExit(timeout time.Duration) {
	s.t.Helper()
	select {
	case <-s.done:
	case <-time.After(timeout):
		s.t.Fatal("terminal shell did not exit")
	}
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
		case inEscape && (c == 'm' || c == 'K' || c == 'J' || c == 'H' || c == 'h' || c == 'l'):
			inEscape = false
		case !inEscape:
			b.WriteByte(c)
		}
	}
	return b.String()
}
