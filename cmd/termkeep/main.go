// termkeep is the Linux TermKeep client. With no subcommand it opens the
// TUI; `status` prints the instance state for scripts and operators.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/davicbtoliveira/TermKeep/internal/client"
	"github.com/davicbtoliveira/TermKeep/internal/session"
	"github.com/davicbtoliveira/TermKeep/internal/tui"
)

// Exit codes for the status command, stable for scripting.
const (
	exitHealthy      = 0
	exitUnavailable  = 1
	exitTLSFailure   = 2
	exitUsageFailure = 64
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("termkeep", flag.ContinueOnError)
	serverURL := fs.String("server", envOr("TERMKEEP_SERVER", "https://localhost"),
		"instance base URL (env TERMKEEP_SERVER)")
	caCert := fs.String("ca-cert", os.Getenv("TERMKEEP_CA_CERT"),
		"PEM file with the deployment CA (env TERMKEEP_CA_CERT)")

	// Parse flags preceding the subcommand; `termkeep status` has no flags
	// of its own yet.
	if err := fs.Parse(args); err != nil {
		return exitUsageFailure
	}

	cfg := client.Config{ServerURL: *serverURL, CACertFile: *caCert}

	switch fs.Arg(0) {
	case "status":
		return runStatus(cfg)
	case "bootstrap":
		return runBootstrap(cfg, fs.Args()[1:])
	case "register":
		return runRegister(cfg, fs.Args()[1:])
	case "login":
		return runLogin(cfg, fs.Args()[1:])
	case "logout":
		return runLogout(fs.Args()[1:])
	case "__session-agent":
		return runSessionAgent(fs.Args()[1:])
	case "":
		return runTUI(cfg)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\nusage: termkeep [--server URL] [--ca-cert FILE] [status|bootstrap|register|login|logout]\n", fs.Arg(0))
		return exitUsageFailure
	}
}

func runBootstrap(cfg client.Config, args []string) int {
	fs := flag.NewFlagSet("bootstrap", flag.ContinueOnError)
	email := fs.String("email", "", "administrator email")
	if err := fs.Parse(args); err != nil || *email == "" || fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: termkeep bootstrap --email EMAIL")
		return exitUsageFailure
	}
	password, err := readMasterPassword("Master password: ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitUsageFailure
	}
	confirmation, err := readMasterPassword("Confirm master password: ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitUsageFailure
	}
	result, err := client.Bootstrap(context.Background(), cfg, client.BootstrapInput{
		Email:                 *email,
		MasterPassword:        password,
		ConfirmMasterPassword: confirmation,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitUsageFailure
	}
	defer result.Vault.Clear()

	fmt.Fprintln(os.Stdout, "Recovery key — save it now. It will not be shown again:")
	fmt.Fprintln(os.Stdout, result.RecoveryKey)
	return runVaultTUI(cfg, "")
}

func runRegister(cfg client.Config, args []string) int {
	fs := flag.NewFlagSet("register", flag.ContinueOnError)
	email := fs.String("email", "", "invited account email")
	inviteToken := fs.String("invite-token", "", "single-use invitation token")
	if err := fs.Parse(args); err != nil || *email == "" || *inviteToken == "" || fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: termkeep register --email EMAIL --invite-token TOKEN")
		return exitUsageFailure
	}
	password, err := readMasterPassword("Master password: ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitUsageFailure
	}
	confirmation, err := readMasterPassword("Confirm master password: ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitUsageFailure
	}
	result, err := client.Register(context.Background(), cfg, client.RegisterInput{
		Email:                 *email,
		InviteToken:           *inviteToken,
		MasterPassword:        password,
		ConfirmMasterPassword: confirmation,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitUsageFailure
	}
	defer result.Vault.Clear()

	fmt.Fprintln(os.Stdout, "Recovery key — save it now. It will not be shown again:")
	fmt.Fprintln(os.Stdout, result.RecoveryKey)
	return runVaultTUI(cfg, "")
}

func runLogin(cfg client.Config, args []string) int {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	email := fs.String("email", "", "account email")
	autoLockValue := fs.String("auto-lock", "", "inactivity timeout in minutes (1-60 or off; default 15)")
	if err := fs.Parse(args); err != nil || *email == "" || fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: termkeep login --email EMAIL [--auto-lock 1-60|off]")
		return exitUsageFailure
	}
	autoLock, err := session.ParseAutoLock(*autoLockValue)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitUsageFailure
	}
	scope, err := session.CurrentScope(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitUsageFailure
	}
	statusCtx, cancelStatus := context.WithTimeout(context.Background(), time.Second)
	info, statusErr := session.Status(statusCtx, scope.SocketPath)
	cancelStatus()
	if statusErr == nil {
		if !strings.EqualFold(strings.TrimSpace(*email), info.Email) {
			fmt.Fprintf(os.Stderr, "error: terminal already unlocked for %s; logout first\n", info.Email)
			return exitUsageFailure
		}
		return runVaultTUI(cfg, scope.SocketPath)
	}

	password, err := readMasterPassword("Master password: ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitUsageFailure
	}
	host, err := os.Hostname()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: read host name:", err)
		return exitUsageFailure
	}
	result, err := client.Login(context.Background(), cfg, client.LoginInput{
		Email:          *email,
		MasterPassword: password,
		Host:           host,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitUsageFailure
	}
	defer result.Clear()
	executable, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: locate session agent executable:", err)
		return exitUsageFailure
	}
	accessToken := []byte(result.AccessToken)
	defer clearPassword(accessToken)
	launchCtx, cancelLaunch := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelLaunch()
	if err := session.Launch(launchCtx, executable, scope, session.UnlockMaterial{
		AccountID:   result.AccountID,
		Email:       strings.ToLower(strings.TrimSpace(*email)),
		VaultKey:    result.VaultKey,
		AccessToken: accessToken,
		ServerURL:   cfg.ServerURL,
		CACertFile:  cfg.CACertFile,
	}, autoLock); err != nil {
		fmt.Fprintln(os.Stderr, "error: start session agent:", err)
		return exitUsageFailure
	}
	return runVaultTUI(cfg, scope.SocketPath)
}

func runSessionAgent(args []string) int {
	startup := os.NewFile(3, "session-startup")
	if err := session.RunAgentProcess(args, startup); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	return 0
}

func runLogout(args []string) int {
	fs := flag.NewFlagSet("logout", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: termkeep logout")
		return exitUsageFailure
	}
	scope, err := session.CurrentScope(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitUsageFailure
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := session.Logout(ctx, scope.SocketPath); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Fprintln(os.Stdout, "Session: locked")
	return 0
}

func runVaultTUI(cfg client.Config, socketPath string) int {
	var token []byte
	if socketPath != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		var err error
		token, err = session.AccessToken(ctx, socketPath)
		cancel()
		if err != nil {
			fmt.Fprintln(os.Stderr, "error: read online session:", err)
			return 1
		}
		defer clearPassword(token)
	}
	if err := tui.RunVault(cfg, string(token), socketPath); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	return 0
}

func readMasterPassword(prompt string) (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf("master password input requires a TTY")
	}
	fmt.Fprint(os.Stderr, prompt)
	value, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	defer clearPassword(value)
	return string(value), nil
}

func clearPassword(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

func runStatus(cfg client.Config) int {
	st, err := client.CheckStatus(context.Background(), cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitUsageFailure
	}
	for _, line := range client.Lines(cfg.ServerURL, st) {
		fmt.Println(line)
	}
	switch st.State {
	case client.StateHealthy:
		return exitHealthy
	case client.StateTLSError:
		return exitTLSFailure
	default:
		return exitUnavailable
	}
}

func runTUI(cfg client.Config) int {
	if err := tui.Run(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	return 0
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
