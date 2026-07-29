package client

import (
	"encoding/base32"
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
