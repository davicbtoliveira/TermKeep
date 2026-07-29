// termkeep is the Linux TermKeep client. With no subcommand it opens the
// TUI; `status` prints the instance state for scripts and operators.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
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

var errSecretUsage = errors.New("invalid secret command usage")
var errTOTPUsage = errors.New("invalid TOTP command usage")
var errPasswordGeneratorUsage = errors.New(
	"invalid password generator command usage",
)
var errImportUsage = errors.New("invalid import command usage")

type secretRequest struct {
	itemID string
	field  string
}

type totpRequest struct {
	itemID string
}

type passwordGeneratorRequest struct {
	config client.PasswordGeneratorConfig
}

type bitwardenImportRequest struct {
	path    string
	confirm bool
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func parseGlobalConfig(args []string) (client.Config, []string, error) {
	fs := flag.NewFlagSet("termkeep", flag.ContinueOnError)
	serverURL := fs.String("server", envOr("TERMKEEP_SERVER", "https://localhost"),
		"instance base URL (env TERMKEEP_SERVER)")
	caCert := fs.String("ca-cert", os.Getenv("TERMKEEP_CA_CERT"),
		"PEM file with the deployment CA (env TERMKEEP_CA_CERT)")
	pwnedPasswordsURL := fs.String(
		"pwned-passwords-url",
		envOr(
			"TERMKEEP_PWNED_PASSWORDS_URL",
			client.DefaultPwnedPasswordsURL,
		),
		"Pwned Passwords range endpoint or off "+
			"(env TERMKEEP_PWNED_PASSWORDS_URL)",
	)

	if err := fs.Parse(args); err != nil {
		return client.Config{}, nil, err
	}
	return client.Config{
		ServerURL:         *serverURL,
		CACertFile:        *caCert,
		DataDir:           os.Getenv("TERMKEEP_DATA_DIR"),
		PwnedPasswordsURL: *pwnedPasswordsURL,
	}, fs.Args(), nil
}

func run(args []string) int {
	cfg, commandArgs, err := parseGlobalConfig(args)
	if err != nil {
		return exitUsageFailure
	}
	var command string
	if len(commandArgs) > 0 {
		command = commandArgs[0]
	}
	switch command {
	case "status":
		return runStatus(cfg)
	case "bootstrap":
		return runBootstrap(cfg, commandArgs[1:])
	case "register":
		return runRegister(cfg, commandArgs[1:])
	case "login":
		return runLogin(cfg, commandArgs[1:])
	case "logout":
		return runLogout(commandArgs[1:])
	case "sync":
		return runSync(cfg, commandArgs[1:])
	case "secret":
		return runSecret(cfg, commandArgs[1:])
	case "totp":
		return runTOTP(cfg, commandArgs[1:])
	case "generate-password":
		return runGeneratePassword(commandArgs[1:])
	case "__session-agent":
		return runSessionAgent(commandArgs[1:])
	case "":
		return runTUI(cfg)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\nusage: termkeep [--server URL] [--ca-cert FILE] [--pwned-passwords-url URL|off] [status|bootstrap|register|login|logout|sync|secret|totp|generate-password]\n", command)
		return exitUsageFailure
	}
}

func runBootstrap(cfg client.Config, args []string) int {
	fs := flag.NewFlagSet("bootstrap", flag.ContinueOnError)
	email := fs.String("email", "", "administrator email")
	recoveryStdout := fs.Bool(
		"stdout-recovery-key",
		false,
		"write the one-time Recovery key to stdout",
	)
	if err := fs.Parse(args); err != nil || *email == "" ||
		!*recoveryStdout || fs.NArg() != 0 {
		fmt.Fprintln(
			os.Stderr,
			"usage: termkeep bootstrap --email EMAIL "+
				"--stdout-recovery-key",
		)
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
	if err := client.AuthorizeCache(
		cfg,
		*email,
		result.AccountID,
		result.Vault.PasswordEnvelope,
	); err != nil {
		fmt.Fprintln(os.Stderr, "error: authorize encrypted cache:", err)
		return exitUsageFailure
	}

	fmt.Fprintln(os.Stdout, "Recovery key — save it now. It will not be shown again:")
	fmt.Fprintln(os.Stdout, result.RecoveryKey)
	return runVaultTUI(cfg, "")
}

func runRegister(cfg client.Config, args []string) int {
	fs := flag.NewFlagSet("register", flag.ContinueOnError)
	email := fs.String("email", "", "invited account email")
	inviteToken := fs.String("invite-token", "", "single-use invitation token")
	recoveryStdout := fs.Bool(
		"stdout-recovery-key",
		false,
		"write the one-time Recovery key to stdout",
	)
	if err := fs.Parse(args); err != nil || *email == "" ||
		*inviteToken == "" || !*recoveryStdout || fs.NArg() != 0 {
		fmt.Fprintln(
			os.Stderr,
			"usage: termkeep register --email EMAIL "+
				"--invite-token TOKEN --stdout-recovery-key",
		)
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
	if err := client.AuthorizeCache(
		cfg,
		*email,
		result.AccountID,
		result.Vault.PasswordEnvelope,
	); err != nil {
		fmt.Fprintln(os.Stderr, "error: authorize encrypted cache:", err)
		return exitUsageFailure
	}

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
	result, _, err := client.LoginWithCache(context.Background(), cfg, client.LoginInput{
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

func runSync(cfg client.Config, args []string) int {
	fs := flag.NewFlagSet("sync", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: termkeep sync")
		return exitUsageFailure
	}
	scope, err := session.CurrentScope(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitUsageFailure
	}
	return runSyncAt(cfg, scope.SocketPath)
}

func runSyncAt(cfg client.Config, socketPath string) int {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	info, err := session.Status(ctx, socketPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: read unlocked session:", err)
		return 1
	}
	token, err := session.AccessToken(ctx, socketPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: read online session:", err)
		return 1
	}
	if len(token) == 0 {
		fmt.Fprintln(os.Stderr, "error: online authentication required")
		return 1
	}
	defer clearPassword(token)
	cache, err := client.OpenCache(cfg, info.Email)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: open encrypted cache:", err)
		return 1
	}
	if err := client.SyncCache(ctx, cfg, string(token), cache); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	snapshot, err := cache.SyncSnapshot()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: read synchronization state:", err)
		return 1
	}
	fmt.Fprintf(os.Stdout, "Sync: complete (%d pending)\n", len(snapshot.Mutations))
	return 0
}

func parseSecretRequest(args []string) (secretRequest, error) {
	fs := flag.NewFlagSet("secret", flag.ContinueOnError)
	itemID := fs.String("item", "", "Item UUID")
	field := fs.String("field", "", "secret field")
	stdout := fs.Bool("stdout", false, "write secret to stdout")
	if err := fs.Parse(args); err != nil ||
		*itemID == "" || *field == "" || !*stdout || fs.NArg() != 0 {
		return secretRequest{}, errSecretUsage
	}
	return secretRequest{itemID: *itemID, field: *field}, nil
}

func parsePasswordGeneratorRequest(
	args []string,
) (passwordGeneratorRequest, error) {
	fs := flag.NewFlagSet("generate-password", flag.ContinueOnError)
	length := fs.Int("length", 20, "password length (5-128)")
	uppercase := fs.Bool("uppercase", true, "include uppercase")
	lowercase := fs.Bool("lowercase", true, "include lowercase")
	digits := fs.Bool("digits", true, "include digits")
	special := fs.Bool("special", true, "include special characters")
	minimumDigits := fs.Int("min-digits", 1, "minimum digits")
	minimumSpecial := fs.Int(
		"min-special",
		1,
		"minimum special characters",
	)
	excludeAmbiguous := fs.Bool(
		"exclude-ambiguous",
		false,
		"exclude ambiguous characters",
	)
	stdout := fs.Bool("stdout", false, "write password to stdout")
	if err := fs.Parse(args); err != nil || !*stdout || fs.NArg() != 0 {
		return passwordGeneratorRequest{}, errPasswordGeneratorUsage
	}
	config := client.PasswordGeneratorConfig{
		Length:           *length,
		Uppercase:        *uppercase,
		Lowercase:        *lowercase,
		Digits:           *digits,
		Special:          *special,
		MinimumDigits:    *minimumDigits,
		MinimumSpecial:   *minimumSpecial,
		ExcludeAmbiguous: *excludeAmbiguous,
	}
	if err := client.ValidatePasswordGeneratorConfig(config); err != nil {
		return passwordGeneratorRequest{}, errPasswordGeneratorUsage
	}
	return passwordGeneratorRequest{config: config}, nil
}

func runSecret(cfg client.Config, args []string) int {
	request, err := parseSecretRequest(args)
	if err != nil {
		fmt.Fprintln(
			os.Stderr,
			"usage: termkeep secret --item UUID "+
				"--field password|notes|content|custom:NAME --stdout",
		)
		return exitUsageFailure
	}
	scope, err := session.CurrentScope(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: read terminal session failed")
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := outputSecretAt(
		ctx, cfg, scope.SocketPath, request, os.Stdout,
	); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	return 0
}

func runGeneratePassword(args []string) int {
	request, err := parsePasswordGeneratorRequest(args)
	if err != nil {
		fmt.Fprintln(
			os.Stderr,
			"usage: termkeep generate-password "+
				"[--length 5-128] "+
				"[--uppercase=true|false] "+
				"[--lowercase=true|false] "+
				"[--digits=true|false] "+
				"[--special=true|false] "+
				"[--min-digits N] [--min-special N] "+
				"[--exclude-ambiguous] --stdout",
		)
		return exitUsageFailure
	}
	if err := outputGeneratedPassword(request.config, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	return 0
}

func parseBitwardenImportRequest(
	args []string,
) (bitwardenImportRequest, error) {
	if len(args) == 0 || args[0] != "bitwarden" {
		return bitwardenImportRequest{}, errImportUsage
	}
	fs := flag.NewFlagSet("import bitwarden", flag.ContinueOnError)
	path := fs.String("file", "", "Bitwarden JSON export")
	confirm := fs.Bool(
		"confirm",
		false,
		"confirm import after preview",
	)
	if err := fs.Parse(args[1:]); err != nil ||
		strings.TrimSpace(*path) == "" ||
		fs.NArg() != 0 {
		return bitwardenImportRequest{}, errImportUsage
	}
	return bitwardenImportRequest{
		path:    strings.TrimSpace(*path),
		confirm: *confirm,
	}, nil
}

func outputGeneratedPassword(
	config client.PasswordGeneratorConfig,
	stdout io.Writer,
) error {
	password, err := client.GeneratePassword(config)
	if err != nil {
		return errors.New("generate password failed")
	}
	if _, err := fmt.Fprintln(stdout, password); err != nil {
		return errors.New("write password output failed")
	}
	return nil
}

func parseTOTPRequest(args []string) (totpRequest, error) {
	fs := flag.NewFlagSet("totp", flag.ContinueOnError)
	itemID := fs.String("item", "", "Item UUID")
	stdout := fs.Bool("stdout", false, "write TOTP code to stdout")
	if err := fs.Parse(args); err != nil ||
		*itemID == "" || !*stdout || fs.NArg() != 0 {
		return totpRequest{}, errTOTPUsage
	}
	return totpRequest{itemID: *itemID}, nil
}

func runTOTP(cfg client.Config, args []string) int {
	request, err := parseTOTPRequest(args)
	if err != nil {
		fmt.Fprintln(
			os.Stderr,
			"usage: termkeep totp --item UUID --stdout",
		)
		return exitUsageFailure
	}
	scope, err := session.CurrentScope(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: read terminal session failed")
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := outputTOTPAt(
		ctx,
		cfg,
		scope.SocketPath,
		request,
		time.Now(),
		os.Stdout,
	); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	return 0
}

func outputSecretAt(
	ctx context.Context,
	cfg client.Config,
	socketPath string,
	request secretRequest,
	stdout io.Writer,
) error {
	opened, err := openNativeItemAt(
		ctx,
		cfg,
		socketPath,
		request.itemID,
	)
	if err != nil {
		return err
	}
	value, err := requestedSecret(opened, request.field)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(stdout, value); err != nil {
		return errors.New("write secret output failed")
	}
	return nil
}

func outputTOTPAt(
	ctx context.Context,
	cfg client.Config,
	socketPath string,
	request totpRequest,
	at time.Time,
	stdout io.Writer,
) error {
	opened, err := openNativeItemAt(
		ctx,
		cfg,
		socketPath,
		request.itemID,
	)
	if err != nil {
		return err
	}
	if opened.Type != client.NativeItemTypeLogin ||
		opened.Login == nil ||
		opened.Login.TOTP == nil {
		return errors.New("TOTP unavailable for Item")
	}
	code, err := client.GenerateTOTP(*opened.Login.TOTP, at)
	if err != nil {
		return errors.New("generate TOTP failed")
	}
	if _, err := fmt.Fprintln(stdout, code.Value); err != nil {
		return errors.New("write TOTP output failed")
	}
	return nil
}

func openNativeItemAt(
	ctx context.Context,
	cfg client.Config,
	socketPath string,
	itemID string,
) (client.NativeItem, error) {
	info, err := session.Status(ctx, socketPath)
	if err != nil {
		return client.NativeItem{},
			errors.New("read unlocked session failed")
	}
	cache, err := client.OpenCache(cfg, info.Email)
	if err != nil {
		return client.NativeItem{},
			errors.New("open encrypted cache failed")
	}
	groups, err := cache.ItemHeads()
	if err != nil {
		return client.NativeItem{},
			errors.New("read encrypted cache failed")
	}
	for _, group := range groups {
		if group.ItemID != itemID {
			continue
		}
		if len(group.Revisions) != 1 ||
			group.Revisions[0].Deleted ||
			group.Revisions[0].Purged {
			return client.NativeItem{}, errors.New(
				"resolve Item conflict before reading secret")
		}
		opened, err := session.OpenNativeItem(
			ctx, socketPath, group.Revisions[0])
		if err != nil {
			return client.NativeItem{},
				errors.New("decrypt Item failed")
		}
		return opened, nil
	}
	return client.NativeItem{}, errors.New("Item not found")
}

func requestedSecret(
	item client.NativeItem,
	field string,
) (string, error) {
	if item.Type == client.NativeItemTypeLogin && item.Login != nil {
		switch field {
		case "password":
			return item.Login.Password, nil
		case "notes":
			return item.Login.Notes, nil
		}
		if name, found := strings.CutPrefix(field, "custom:"); found &&
			name != "" {
			for _, customField := range item.Login.CustomFields {
				if customField.Name == name {
					return customField.Value, nil
				}
			}
		}
	}
	if field == "content" &&
		item.Type == client.NativeItemTypeSecureNote &&
		item.SecureNote != nil {
		return item.SecureNote.Content, nil
	}
	return "", errors.New("secret field unavailable for Item")
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
