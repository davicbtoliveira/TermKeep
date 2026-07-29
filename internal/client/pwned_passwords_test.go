package client

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCheckPwnedPasswordSendsOnlyHashPrefixAndFindsCount(
	t *testing.T,
) {
	const password = "Password-Sentinel#2026"
	sum := sha1.Sum([]byte(password))
	fullHash := strings.ToUpper(hex.EncodeToString(sum[:]))
	prefix := fullHash[:5]
	suffix := fullHash[5:]
	var requestSurface string
	server := httptest.NewServer(http.HandlerFunc(func(
		w http.ResponseWriter,
		r *http.Request,
	) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		requestSurface = r.Method + " " +
			r.URL.RequestURI() + "\n" +
			headerSurface(r.Header) + "\n" +
			string(body)
		if r.Method != http.MethodGet ||
			r.URL.Path != "/range/"+prefix ||
			r.URL.RawQuery != "" ||
			r.Header.Get("Add-Padding") != "true" ||
			r.Header.Get("User-Agent") == "" {
			t.Fatalf("unexpected range request: %s", requestSurface)
		}
		_, _ = io.WriteString(w, suffix+":42\r\n")
	}))
	defer server.Close()

	result := CheckPwnedPassword(
		context.Background(),
		Config{PwnedPasswordsURL: server.URL + "/range"},
		password,
	)
	if result.Status != PwnedPasswordFound || result.Count != 42 {
		t.Fatalf("pwned result: %+v", result)
	}
	for _, forbidden := range []string{
		password,
		fullHash,
		suffix,
		"user-email-sentinel@example.com",
		"https://login-domain-sentinel.example.com",
		"login-domain-sentinel.example.com",
	} {
		if strings.Contains(requestSurface, forbidden) {
			t.Fatalf("range request exposed %q: %s",
				forbidden, requestSurface)
		}
	}
}

func TestCheckPwnedPasswordDistinguishesOutcomeStates(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
		want       PwnedPasswordStatus
	}{
		{
			name:       "not found",
			statusCode: http.StatusOK,
			body:       strings.Repeat("A", 35) + ":7\r\n",
			want:       PwnedPasswordNotFound,
		},
		{
			name:       "unavailable",
			statusCode: http.StatusServiceUnavailable,
			want:       PwnedPasswordUnavailable,
		},
		{
			name:       "malformed response",
			statusCode: http.StatusOK,
			body:       "not-a-range-response\r\n",
			want:       PwnedPasswordInvalidResponse,
		},
		{
			name:       "empty response",
			statusCode: http.StatusOK,
			want:       PwnedPasswordInvalidResponse,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(
				w http.ResponseWriter,
				_ *http.Request,
			) {
				w.WriteHeader(test.statusCode)
				_, _ = io.WriteString(w, test.body)
			}))
			defer server.Close()
			result := CheckPwnedPassword(
				context.Background(),
				Config{
					PwnedPasswordsURL: server.URL + "/range",
				},
				"Password-Sentinel#2026",
			)
			if result.Status != test.want || result.Count != 0 {
				t.Fatalf(
					"want status %v/count 0, got %+v",
					test.want,
					result,
				)
			}
		})
	}

	result := CheckPwnedPassword(
		context.Background(),
		Config{PwnedPasswordsURL: "off"},
		"Password-Sentinel#2026",
	)
	if result.Status != PwnedPasswordDisabled || result.Count != 0 {
		t.Fatalf("disabled result: %+v", result)
	}
}

func headerSurface(header http.Header) string {
	var surface strings.Builder
	for name, values := range header {
		surface.WriteString(name)
		surface.WriteString(":")
		surface.WriteString(strings.Join(values, ","))
		surface.WriteString("\n")
	}
	return surface.String()
}
