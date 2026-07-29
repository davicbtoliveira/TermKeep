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
