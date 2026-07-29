package client

import (
	"encoding/base32"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestGenerateHOTPMatchesRFC4226(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString(
		[]byte("12345678901234567890"),
	)
	want := []string{
		"755224",
		"287082",
		"359152",
		"969429",
		"338314",
		"254676",
		"287922",
		"162583",
		"399871",
		"520489",
	}

	for counter, expected := range want {
		got, err := GenerateHOTP(
			secret,
			TOTPAlgorithmSHA1,
			6,
			uint64(counter),
		)
		if err != nil {
			t.Fatalf("counter %d: %v", counter, err)
		}
		if got != expected {
			t.Fatalf(
				"counter %d: want %s, got %s",
				counter,
				expected,
				got,
			)
		}
	}
}

func TestGenerateTOTPMatchesRFC6238Algorithms(t *testing.T) {
	tests := []struct {
		name      string
		algorithm TOTPAlgorithm
		secret    string
		want      string
	}{
		{
			name:      "SHA1",
			algorithm: TOTPAlgorithmSHA1,
			secret:    "12345678901234567890",
			want:      "94287082",
		},
		{
			name:      "SHA256",
			algorithm: TOTPAlgorithmSHA256,
			secret:    "12345678901234567890123456789012",
			want:      "46119246",
		},
		{
			name:      "SHA512",
			algorithm: TOTPAlgorithmSHA512,
			secret: "12345678901234567890123456789012" +
				"34567890123456789012345678901234",
			want: "90693936",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := TOTPConfig{
				Secret: base32.StdEncoding.EncodeToString(
					[]byte(test.secret),
				),
				Algorithm: test.algorithm,
				Digits:    8,
				Period:    30,
			}
			code, err := GenerateTOTP(config, time.Unix(59, 0))
			if err != nil {
				t.Fatal(err)
			}
			if code.Value != test.want {
				t.Fatalf(
					"code: want %s, got %s",
					test.want,
					code.Value,
				)
			}
			if want := time.Unix(60, 0); !code.ExpiresAt.Equal(want) {
				t.Fatalf(
					"expiration: want %s, got %s",
					want,
					code.ExpiresAt,
				)
			}
		})
	}
}

func TestGenerateTOTPUsesConfiguredDigitsAndPeriod(t *testing.T) {
	config := TOTPConfig{
		Secret:    "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
		Algorithm: TOTPAlgorithmSHA1,
		Digits:    6,
		Period:    45,
	}
	code, err := GenerateTOTP(config, time.Unix(59, 0))
	if err != nil {
		t.Fatal(err)
	}
	if code.Value != "287082" {
		t.Fatalf("code: want 287082, got %s", code.Value)
	}
	if want := time.Unix(90, 0); !code.ExpiresAt.Equal(want) {
		t.Fatalf(
			"expiration: want %s, got %s",
			want,
			code.ExpiresAt,
		)
	}
}

func TestParseTOTPURIKeepsSupportedParameters(t *testing.T) {
	config, err := ParseTOTPURI(
		"otpauth://totp/Example%20Co:alice%40example.com?" +
			"secret=JBSWY3DPEHPK3PXP&issuer=Example%20Co&" +
			"algorithm=SHA256&digits=8&period=45",
	)
	if err != nil {
		t.Fatal(err)
	}
	want := TOTPConfig{
		Secret:    "JBSWY3DPEHPK3PXP",
		Issuer:    "Example Co",
		Account:   "alice@example.com",
		Algorithm: TOTPAlgorithmSHA256,
		Digits:    8,
		Period:    45,
	}
	if !reflect.DeepEqual(config, want) {
		t.Fatalf("parsed config:\nwant: %+v\ngot:  %+v", want, config)
	}
}

func TestTOTPInputsApplyStandardDefaults(t *testing.T) {
	fromURI, err := ParseTOTPURI(
		"otpauth://totp/alice@example.com?secret=JBSWY3DPEHPK3PXP",
	)
	if err != nil {
		t.Fatal(err)
	}
	fromManual, err := NewTOTPConfig(
		"JBSWY3DPEHPK3PXP",
		"",
		"alice@example.com",
		"",
		0,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}

	want := TOTPConfig{
		Secret:    "JBSWY3DPEHPK3PXP",
		Account:   "alice@example.com",
		Algorithm: TOTPAlgorithmSHA1,
		Digits:    6,
		Period:    30,
	}
	if !reflect.DeepEqual(fromURI, want) {
		t.Fatalf("URI defaults:\nwant: %+v\ngot:  %+v", want, fromURI)
	}
	if !reflect.DeepEqual(fromManual, want) {
		t.Fatalf("manual defaults:\nwant: %+v\ngot:  %+v", want, fromManual)
	}
}

func TestNewTOTPConfigAcceptsManualParameters(t *testing.T) {
	got, err := NewTOTPConfig(
		"JBSWY3DPEHPK3PXP",
		"Example Co",
		"alice@example.com",
		"sha512",
		8,
		60,
	)
	if err != nil {
		t.Fatal(err)
	}
	want := TOTPConfig{
		Secret:    "JBSWY3DPEHPK3PXP",
		Issuer:    "Example Co",
		Account:   "alice@example.com",
		Algorithm: TOTPAlgorithmSHA512,
		Digits:    8,
		Period:    60,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("manual config:\nwant: %+v\ngot:  %+v", want, got)
	}
}

func TestTOTPInputsRejectInvalidValues(t *testing.T) {
	tests := []struct {
		name string
		run  func() error
	}{
		{
			name: "URI scheme",
			run: func() error {
				_, err := ParseTOTPURI(
					"https://totp/alice?secret=JBSWY3DPEHPK3PXP",
				)
				return err
			},
		},
		{
			name: "HOTP URI",
			run: func() error {
				_, err := ParseTOTPURI(
					"otpauth://hotp/alice?" +
						"secret=JBSWY3DPEHPK3PXP&counter=0",
				)
				return err
			},
		},
		{
			name: "issuer mismatch",
			run: func() error {
				_, err := ParseTOTPURI(
					"otpauth://totp/First:alice?" +
						"secret=JBSWY3DPEHPK3PXP&issuer=Second",
				)
				return err
			},
		},
		{
			name: "invalid secret",
			run: func() error {
				_, err := NewTOTPConfig("not-base32!", "", "", "", 0, 0)
				return err
			},
		},
		{
			name: "invalid algorithm",
			run: func() error {
				_, err := NewTOTPConfig(
					"JBSWY3DPEHPK3PXP", "", "", "MD5", 6, 30,
				)
				return err
			},
		},
		{
			name: "invalid digits",
			run: func() error {
				_, err := NewTOTPConfig(
					"JBSWY3DPEHPK3PXP", "", "", "SHA1", 7, 30,
				)
				return err
			},
		},
		{
			name: "invalid period",
			run: func() error {
				_, err := NewTOTPConfig(
					"JBSWY3DPEHPK3PXP", "", "", "SHA1", 6, -1,
				)
				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.run(); !errors.Is(err, ErrInvalidTOTP) {
				t.Fatalf("want ErrInvalidTOTP, got %v", err)
			}
		})
	}
}
