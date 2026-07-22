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
func NewHandler(version string, schema SchemaStore, trustedProxies []netip.Prefix, auth ...*AuthService) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/api/v1/status", statusHandler(version, schema, trustedProxies))
	if len(auth) != 0 && auth[0] != nil {
		auth[0].register(mux)
	}
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

// clientIP resolves the effective client address. The header is read only
// when the direct peer is a trusted proxy; resolution then walks
// X-Forwarded-For right to left, skipping trusted hops, and stops at the
// first address outside the trusted set. This defeats clients that prepend
// forged entries, which a pass-through proxy would otherwise preserve.
func clientIP(r *http.Request, trusted []netip.Prefix) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	remote, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	if !isTrusted(remote, trusted) {
		return remote.String()
	}

	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return remote.String()
	}
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		candidate := strings.TrimSpace(parts[i])
		ip, err := netip.ParseAddr(candidate)
		if err != nil || !isTrusted(ip, trusted) {
			return candidate
		}
	}
	return remote.String()
}

func isTrusted(ip netip.Addr, trusted []netip.Prefix) bool {
	for _, p := range trusted {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}
