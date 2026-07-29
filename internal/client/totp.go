package client

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var ErrInvalidTOTP = errors.New("invalid TOTP configuration")

type TOTPAlgorithm string

const (
	TOTPAlgorithmSHA1   TOTPAlgorithm = "SHA1"
	TOTPAlgorithmSHA256 TOTPAlgorithm = "SHA256"
	TOTPAlgorithmSHA512 TOTPAlgorithm = "SHA512"
)

type TOTPConfig struct {
	Secret    string        `json:"secret"`
	Issuer    string        `json:"issuer,omitempty"`
	Account   string        `json:"account,omitempty"`
	Algorithm TOTPAlgorithm `json:"algorithm"`
	Digits    int           `json:"digits"`
	Period    int           `json:"period"`
}

type TOTPCode struct {
	Value     string
	ExpiresAt time.Time
}

func ParseTOTPURI(raw string) (TOTPConfig, error) {
	parsed, err := url.Parse(raw)
	if err != nil ||
		!strings.EqualFold(parsed.Scheme, "otpauth") ||
		!strings.EqualFold(parsed.Host, "totp") ||
		parsed.User != nil ||
		parsed.Fragment != "" {
		return TOTPConfig{}, ErrInvalidTOTP
	}
	label := strings.TrimPrefix(parsed.Path, "/")
	if label == "" || strings.Contains(label, "/") {
		return TOTPConfig{}, ErrInvalidTOTP
	}

	account := label
	labelIssuer := ""
	if issuer, remainder, found := strings.Cut(label, ":"); found {
		if issuer == "" || remainder == "" {
			return TOTPConfig{}, ErrInvalidTOTP
		}
		labelIssuer = issuer
		account = remainder
	}

	query := parsed.Query()
	secret, err := totpQueryValue(query, "secret")
	if err != nil {
		return TOTPConfig{}, err
	}
	issuer, err := totpQueryValue(query, "issuer")
	if err != nil {
		return TOTPConfig{}, err
	}
	if issuer == "" {
		issuer = labelIssuer
	} else if labelIssuer != "" && issuer != labelIssuer {
		return TOTPConfig{}, ErrInvalidTOTP
	}
	algorithm, err := totpQueryValue(query, "algorithm")
	if err != nil {
		return TOTPConfig{}, err
	}
	digits, err := totpQueryInt(query, "digits")
	if err != nil {
		return TOTPConfig{}, err
	}
	period, err := totpQueryInt(query, "period")
	if err != nil {
		return TOTPConfig{}, err
	}
	return NewTOTPConfig(
		secret,
		issuer,
		account,
		algorithm,
		digits,
		period,
	)
}

func NewTOTPConfig(
	secret string,
	issuer string,
	account string,
	algorithm string,
	digits int,
	period int,
) (TOTPConfig, error) {
	if algorithm == "" {
		algorithm = string(TOTPAlgorithmSHA1)
	}
	if digits == 0 {
		digits = 6
	}
	if period == 0 {
		period = 30
	}
	config := TOTPConfig{
		Secret:    secret,
		Issuer:    issuer,
		Account:   account,
		Algorithm: TOTPAlgorithm(strings.ToUpper(algorithm)),
		Digits:    digits,
		Period:    period,
	}
	if err := ValidateTOTPConfig(config); err != nil {
		return TOTPConfig{}, err
	}
	return config, nil
}

func ValidateTOTPConfig(config TOTPConfig) error {
	secret, err := decodeTOTPSecret(config.Secret)
	if err != nil {
		return ErrInvalidTOTP
	}
	clearBytes(secret)
	if _, err := totpHash(config.Algorithm); err != nil {
		return ErrInvalidTOTP
	}
	if _, err := totpDivisor(config.Digits); err != nil {
		return ErrInvalidTOTP
	}
	if config.Period <= 0 {
		return ErrInvalidTOTP
	}
	return nil
}

func GenerateHOTP(
	secret string,
	algorithm TOTPAlgorithm,
	digits int,
	counter uint64,
) (string, error) {
	decodedSecret, err := decodeTOTPSecret(secret)
	if err != nil {
		return "", err
	}
	defer clearBytes(decodedSecret)
	newHash, err := totpHash(algorithm)
	if err != nil {
		return "", err
	}
	divisor, err := totpDivisor(digits)
	if err != nil {
		return "", err
	}

	message := make([]byte, 8)
	binary.BigEndian.PutUint64(message, counter)
	mac := hmac.New(newHash, decodedSecret)
	_, _ = mac.Write(message)
	sum := mac.Sum(nil)
	defer clearBytes(sum)
	offset := int(sum[len(sum)-1] & 0x0f)
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) &
		0x7fffffff
	return fmt.Sprintf("%0*d", digits, value%divisor), nil
}

func GenerateTOTP(config TOTPConfig, at time.Time) (TOTPCode, error) {
	if ValidateTOTPConfig(config) != nil || at.Unix() < 0 {
		return TOTPCode{}, ErrInvalidTOTP
	}
	counter := uint64(at.Unix() / int64(config.Period))
	value, err := GenerateHOTP(
		config.Secret,
		config.Algorithm,
		config.Digits,
		counter,
	)
	if err != nil {
		return TOTPCode{}, err
	}
	return TOTPCode{
		Value: value,
		ExpiresAt: time.Unix(
			int64(counter+1)*int64(config.Period),
			0,
		),
	}, nil
}

func decodeTOTPSecret(secret string) ([]byte, error) {
	secret = strings.ToUpper(strings.Join(strings.Fields(secret), ""))
	secret = strings.TrimRight(secret, "=")
	if secret == "" {
		return nil, ErrInvalidTOTP
	}
	decoded, err := base32.StdEncoding.WithPadding(
		base32.NoPadding,
	).DecodeString(secret)
	if err != nil || len(decoded) == 0 {
		return nil, ErrInvalidTOTP
	}
	return decoded, nil
}

func totpHash(
	algorithm TOTPAlgorithm,
) (func() hash.Hash, error) {
	switch algorithm {
	case TOTPAlgorithmSHA1:
		return sha1.New, nil
	case TOTPAlgorithmSHA256:
		return sha256.New, nil
	case TOTPAlgorithmSHA512:
		return sha512.New, nil
	default:
		return nil, ErrInvalidTOTP
	}
}

func totpDivisor(digits int) (uint32, error) {
	switch digits {
	case 6:
		return 1_000_000, nil
	case 8:
		return 100_000_000, nil
	default:
		return 0, ErrInvalidTOTP
	}
}

func totpQueryValue(
	query url.Values,
	key string,
) (string, error) {
	values, found := query[key]
	if !found {
		return "", nil
	}
	if len(values) != 1 {
		return "", ErrInvalidTOTP
	}
	return values[0], nil
}

func totpQueryInt(query url.Values, key string) (int, error) {
	value, err := totpQueryValue(query, key)
	if err != nil || value == "" {
		return 0, err
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, ErrInvalidTOTP
	}
	return parsed, nil
}
