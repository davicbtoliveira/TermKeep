// termkeep-server is the self-hosted TermKeep API. It applies schema
// migrations at boot and serves /api/v1 behind a TLS-terminating proxy.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/davicbtoliveira/TermKeep/internal/server"
)

// version is stamped at build time:
//
//	go build -ldflags "-X main.version=$(git describe --tags --always)"
var version = "dev"

func main() {
	if len(os.Args) == 2 && os.Args[1] == "opaque-keygen" {
		privateKey, oprfSeed, err := server.GenerateOPAQUEKeyMaterial()
		if err != nil {
			slog.Error("generate OPAQUE key material", "error", err)
			os.Exit(1)
		}
		fmt.Printf("OPAQUE_SERVER_KEY=%s\nOPAQUE_OPRF_SEED=%s\n", privateKey, oprfSeed)
		return
	}
	if err := run(); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run() error {
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		return errors.New("DATABASE_URL is required")
	}

	trusted, err := parseProxies(os.Getenv("TRUSTED_PROXIES"))
	if err != nil {
		return err
	}
	opaqueServer, err := server.NewOPAQUEServer(
		os.Getenv("OPAQUE_SERVER_KEY"),
		os.Getenv("OPAQUE_OPRF_SEED"),
	)
	if err != nil {
		return err
	}

	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	db, err := server.OpenDB(ctx, databaseURL)
	if err != nil {
		return err
	}
	defer db.Close()

	schemaVersion, err := server.Apply(ctx, db)
	if err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}
	slog.Info("migrations applied", "schema_version", schemaVersion)

	dbStore := server.DBStore{DB: db}
	auth := server.NewAuthService(opaqueServer, dbStore)
	invites := server.NewInviteService(dbStore, auth)
	srv := &http.Server{
		Addr:              addr,
		Handler:           server.NewHandler(version, dbStore, trusted, auth, invites),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	slog.Info("listening", "addr", addr, "version", version, "trusted_proxies", os.Getenv("TRUSTED_PROXIES"))
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// parseProxies converts a comma-separated CIDR list into prefixes. An empty
// value trusts nothing: forwarded headers are then ignored everywhere.
func parseProxies(value string) ([]netip.Prefix, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	var out []netip.Prefix
	for _, part := range strings.Split(value, ",") {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(part))
		if err != nil {
			return nil, fmt.Errorf("TRUSTED_PROXIES: parse %q: %w", part, err)
		}
		out = append(out, prefix)
	}
	return out, nil
}
