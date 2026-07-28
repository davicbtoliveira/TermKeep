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
	case StateClientOffline:
		lines = append(lines,
			"Status:   Client offline",
			"Detail:   "+st.Detail,
		)
	case StateServerUnavailable:
		lines = append(lines,
			"Status:   Server unavailable",
			"Detail:   "+st.Detail,
		)
	case StateConnectionUnavailable:
		lines = append(lines,
			"Status:   Connection unavailable",
			"Detail:   "+st.Detail,
		)
	}
	return lines
}
