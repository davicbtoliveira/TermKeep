package client

import "fmt"

// Lines renders a Status for humans. The CLI status command and the TUI
// share this wording so both surfaces always present the same state.
func Lines(serverURL string, st Status) []string {
	lines := []string{
		fmt.Sprintf("Instance: %s", serverURL),
	}
	switch st.State {
	case StateHealthy:
		lines = append(lines,
			"Status:   healthy",
			fmt.Sprintf("Server:   %s (schema v%d)", st.Version, st.SchemaVersion),
		)
	case StateTLSError:
		lines = append(lines,
			"Status:   TLS validation failed",
			"Detail:   "+st.Detail,
		)
	case StateUnreachable:
		lines = append(lines,
			"Status:   unavailable (unreachable)",
			"Detail:   "+st.Detail,
		)
	case StateUnavailable:
		lines = append(lines,
			"Status:   unavailable (instance unhealthy)",
			"Detail:   "+st.Detail,
		)
	}
	return lines
}
