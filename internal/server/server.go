// Package server implements the TermKeep API: a versioned HTTP/JSON surface
// that serves instance status and, in later slices, synchronization.
package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// SchemaStore reports the applied database schema version. It is the seam
// that lets the status surface prove database reachability on every call.
type SchemaStore interface {
	SchemaVersion(ctx context.Context) (int, error)
}

// StatusResponse is the public body of GET /api/v1/status. It carries no
// secrets; operators and clients use it to classify instance health.
type StatusResponse struct {
	Status        string `json:"status"`
	Version       string `json:"version"`
	SchemaVersion int    `json:"schema_version,omitempty"`
	ClientIP      string `json:"client_ip"`
}

// NewHandler builds the /api/v1 mux. trustedProxies lists the CIDR ranges
// (e.g. the Docker network Traefik lives in) whose X-Forwarded-For headers
// are honored; the header is ignored from any other source.
func NewHandler(version string, schema SchemaStore, trustedProxies []netip.Prefix) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/api/v1/status", statusHandler(version, schema, trustedProxies))
	return mux
}

func statusHandler(version string, schema SchemaStore, trusted []netip.Prefix) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		schemaVersion, err := schema.SchemaVersion(r.Context())
		if err != nil {
			slog.Warn("status: database unreachable", "error", err)
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(StatusResponse{
				Status:   "unavailable",
				Version:  version,
				ClientIP: clientIP(r, trusted),
			})
			return
		}

		_ = json.NewEncoder(w).Encode(StatusResponse{
			Status:        "ok",
			Version:       version,
			SchemaVersion: schemaVersion,
			ClientIP:      clientIP(r, trusted),
		})
	}
}

// clientIP resolves the effective client address. X-Forwarded-For is only
// read when the direct peer belongs to a configured trusted proxy range.
func clientIP(r *http.Request, trusted []netip.Prefix) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	remote, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}

	for _, p := range trusted {
		if p.Contains(remote) {
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				// Leftmost entry is the original client; later entries are
				// the proxies that appended themselves.
				return strings.TrimSpace(strings.Split(xff, ",")[0])
			}
		}
	}
	return remote.String()
}
