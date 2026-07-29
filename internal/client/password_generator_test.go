package client

import (
	"errors"
	"strings"
	"testing"
)

func TestGeneratePasswordSatisfiesSelectedConstraints(t *testing.T) {
	config := PasswordGeneratorConfig{
		Length:         32,
		Uppercase:      true,
		Lowercase:      true,
		Digits:         true,
		Special:        true,
		MinimumDigits:  3,
		MinimumSpecial: 2,
	}

	password, err := GeneratePassword(config)
	if err != nil {
		t.Fatal(err)
	}
	if len(password) != config.Length {
		t.Fatalf("length: want %d, got %d", config.Length, len(password))
	}
	if countPasswordCharacters(password, PasswordDigits) <
		config.MinimumDigits {
		t.Fatalf("minimum digits not met: %q", password)
	}
	if countPasswordCharacters(password, PasswordSpecialCharacters) <
		config.MinimumSpecial {
		t.Fatalf("minimum special characters not met: %q", password)
	}
	allowed := PasswordUppercaseCharacters +
		PasswordLowercaseCharacters +
		PasswordDigits +
		PasswordSpecialCharacters
	for _, character := range password {
		if !strings.ContainsRune(allowed, character) {
			t.Fatalf("password contains disallowed character %q", character)
		}
	}
}

func TestPasswordGeneratorRejectsLengthOutsideSupportedRange(t *testing.T) {
	for _, length := range []int{4, 129} {
		config := PasswordGeneratorConfig{
			Length:    length,
			Lowercase: true,
		}
		if err := ValidatePasswordGeneratorConfig(config); err == nil {
			t.Fatalf("length %d unexpectedly validated", length)
		}
		if _, err := GeneratePassword(config); err == nil {
			t.Fatalf("length %d unexpectedly generated", length)
		}
	}
}

func TestPasswordGeneratorRejectsImpossibleComposition(t *testing.T) {
	tests := []struct {
		name   string
		config PasswordGeneratorConfig
	}{
		{
			name:   "no character set",
			config: PasswordGeneratorConfig{Length: 20},
		},
		{
			name: "digit minimum without digits",
			config: PasswordGeneratorConfig{
				Length:        20,
				Lowercase:     true,
				MinimumDigits: 1,
			},
		},
		{
			name: "special minimum without special characters",
			config: PasswordGeneratorConfig{
				Length:         20,
				Lowercase:      true,
				MinimumSpecial: 1,
			},
		},
		{
			name: "minimums exceed length",
			config: PasswordGeneratorConfig{
				Length:         5,
				Digits:         true,
				Special:        true,
				MinimumDigits:  3,
				MinimumSpecial: 3,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidatePasswordGeneratorConfig(test.config)
			if !errors.Is(err, ErrInvalidPasswordGeneratorConfig) {
				t.Fatalf(
					"want ErrInvalidPasswordGeneratorConfig, got %v",
					err,
				)
			}
			if _, err := GeneratePassword(test.config); !errors.Is(
				err,
				ErrInvalidPasswordGeneratorConfig,
			) {
				t.Fatalf(
					"generation error: want invalid config, got %v",
					err,
				)
			}
		})
	}
}

func countPasswordCharacters(value string, characters string) int {
	var count int
	for _, character := range value {
		if strings.ContainsRune(characters, character) {
			count++
		}
	}
	return count
}
