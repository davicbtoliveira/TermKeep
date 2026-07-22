// termkeep is the Linux TermKeep client. With no subcommand it opens the
// TUI; `status` prints the instance state for scripts and operators.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/davicbtoliveira/TermKeep/internal/client"
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
	_ = fs.Parse(args)

	cfg := client.Config{ServerURL: *serverURL, CACertFile: *caCert}

	switch fs.Arg(0) {
	case "status":
		return runStatus(cfg)
	case "":
		return runTUI(cfg)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\nusage: termkeep [--server URL] [--ca-cert FILE] [status]\n", fs.Arg(0))
		return exitUsageFailure
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
