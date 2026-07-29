package client

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const DefaultPwnedPasswordsURL = "https://api.pwnedpasswords.com/range"
const maxPwnedPasswordsResponse = 1 << 20

var errInvalidPwnedPasswordsEndpoint = errors.New(
	"invalid Pwned Passwords endpoint",
)

type PwnedPasswordStatus uint8

const (
	PwnedPasswordDisabled PwnedPasswordStatus = iota
	PwnedPasswordNotFound
	PwnedPasswordFound
	PwnedPasswordUnavailable
	PwnedPasswordInvalidResponse
)

type PwnedPasswordResult struct {
	Status PwnedPasswordStatus
	Count  uint64
}

func CheckPwnedPassword(
	ctx context.Context,
	cfg Config,
	password string,
) PwnedPasswordResult {
	rawEndpoint := strings.TrimSpace(cfg.PwnedPasswordsURL)
	if rawEndpoint == "" || strings.EqualFold(rawEndpoint, "off") {
		return PwnedPasswordResult{Status: PwnedPasswordDisabled}
	}

	sum := sha1.Sum([]byte(password))
	defer clearBytes(sum[:])
	var encoded [sha1.Size * 2]byte
	hex.Encode(encoded[:], sum[:])
	for index, character := range encoded {
		if character >= 'a' && character <= 'f' {
			encoded[index] = character - ('a' - 'A')
		}
	}
	defer clearBytes(encoded[:])
	prefix := string(encoded[:5])
	suffix := string(encoded[5:])

	endpoint, err := pwnedPasswordsEndpoint(rawEndpoint, prefix)
	if err != nil {
		return PwnedPasswordResult{Status: PwnedPasswordUnavailable}
	}
	httpClient, err := newHTTPClient(cfg)
	if err != nil {
		return PwnedPasswordResult{Status: PwnedPasswordUnavailable}
	}
	httpClient.CheckRedirect = func(
		_ *http.Request,
		_ []*http.Request,
	) error {
		return http.ErrUseLastResponse
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	requestCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(
		requestCtx,
		http.MethodGet,
		endpoint,
		nil,
	)
	if err != nil {
		return PwnedPasswordResult{Status: PwnedPasswordUnavailable}
	}
	request.Header.Set("Add-Padding", "true")
	request.Header.Set("User-Agent", "TermKeep")
	response, err := httpClient.Do(request)
	if err != nil {
		return PwnedPasswordResult{Status: PwnedPasswordUnavailable}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return PwnedPasswordResult{Status: PwnedPasswordUnavailable}
	}

	body, err := io.ReadAll(io.LimitReader(
		response.Body,
		maxPwnedPasswordsResponse+1,
	))
	if err != nil {
		return PwnedPasswordResult{Status: PwnedPasswordUnavailable}
	}
	defer clearBytes(body)
	if len(body) > maxPwnedPasswordsResponse {
		return PwnedPasswordResult{Status: PwnedPasswordInvalidResponse}
	}
	return parsePwnedPasswordsRange(body, suffix)
}

func pwnedPasswordsEndpoint(
	rawEndpoint string,
	prefix string,
) (string, error) {
	if err := validateServerURL(rawEndpoint); err != nil {
		return "", err
	}
	endpoint, err := url.Parse(rawEndpoint)
	if err != nil ||
		endpoint.Host == "" ||
		endpoint.User != nil ||
		endpoint.RawQuery != "" ||
		endpoint.Fragment != "" {
		return "", errInvalidPwnedPasswordsEndpoint
	}
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/" + prefix
	endpoint.RawPath = ""
	return endpoint.String(), nil
}

func parsePwnedPasswordsRange(
	body []byte,
	wantedSuffix string,
) PwnedPasswordResult {
	var (
		found      bool
		foundCount uint64
		records    int
	)
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			continue
		}
		records++
		suffix, countValue, ok := strings.Cut(line, ":")
		if !ok ||
			len(suffix) != 35 ||
			!isHexString(suffix) {
			return PwnedPasswordResult{
				Status: PwnedPasswordInvalidResponse,
			}
		}
		count, err := strconv.ParseUint(countValue, 10, 64)
		if err != nil {
			return PwnedPasswordResult{
				Status: PwnedPasswordInvalidResponse,
			}
		}
		if !strings.EqualFold(suffix, wantedSuffix) {
			continue
		}
		if found {
			return PwnedPasswordResult{
				Status: PwnedPasswordInvalidResponse,
			}
		}
		found = true
		foundCount = count
	}
	if records == 0 {
		return PwnedPasswordResult{
			Status: PwnedPasswordInvalidResponse,
		}
	}
	if found && foundCount > 0 {
		return PwnedPasswordResult{
			Status: PwnedPasswordFound,
			Count:  foundCount,
		}
	}
	return PwnedPasswordResult{Status: PwnedPasswordNotFound}
}

func isHexString(value string) bool {
	for _, character := range value {
		if !((character >= '0' && character <= '9') ||
			(character >= 'A' && character <= 'F') ||
			(character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}
