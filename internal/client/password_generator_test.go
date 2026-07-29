package client

import (
	"errors"
	"math/rand"
	"strings"
	"testing"
	"testing/quick"
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

func TestGeneratePasswordExcludesDocumentedAmbiguousCharacters(t *testing.T) {
	config := PasswordGeneratorConfig{
		Length:           128,
		Uppercase:        true,
		Lowercase:        true,
		Digits:           true,
		Special:          true,
		MinimumDigits:    32,
		MinimumSpecial:   32,
		ExcludeAmbiguous: true,
	}

	for range 20 {
		password, err := GeneratePassword(config)
		if err != nil {
			t.Fatal(err)
		}
		if strings.ContainsAny(
			password,
			PasswordAmbiguousCharacters,
		) {
			t.Fatalf("password contains ambiguous character: %q", password)
		}
	}
}

func TestGeneratePasswordPropertiesAcrossConfigurations(t *testing.T) {
	property := func(
		lengthSeed uint8,
		selectionSeed uint8,
		digitSeed uint8,
		specialSeed uint8,
		excludeAmbiguous bool,
	) bool {
		config := PasswordGeneratorConfig{
			Length:           5 + int(lengthSeed)%124,
			Uppercase:        selectionSeed&1 != 0,
			Lowercase:        selectionSeed&2 != 0,
			Digits:           selectionSeed&4 != 0,
			Special:          selectionSeed&8 != 0,
			ExcludeAmbiguous: excludeAmbiguous,
		}
		if !config.Uppercase &&
			!config.Lowercase &&
			!config.Digits &&
			!config.Special {
			config.Lowercase = true
		}
		remaining := config.Length
		if config.Digits {
			config.MinimumDigits =
				int(digitSeed) % (remaining + 1)
			remaining -= config.MinimumDigits
		}
		if config.Special {
			config.MinimumSpecial =
				int(specialSeed) % (remaining + 1)
		}

		if ValidatePasswordGeneratorConfig(config) != nil {
			return false
		}
		password, err := GeneratePassword(config)
		if err != nil || len(password) != config.Length {
			return false
		}
		allowed := allowedPasswordCharacters(config)
		for _, character := range password {
			if !strings.ContainsRune(allowed, character) {
				return false
			}
		}
		if countPasswordCharacters(password, PasswordDigits) <
			config.MinimumDigits ||
			countPasswordCharacters(
				password,
				PasswordSpecialCharacters,
			) < config.MinimumSpecial {
			return false
		}
		return !config.ExcludeAmbiguous ||
			!strings.ContainsAny(
				password,
				PasswordAmbiguousCharacters,
			)
	}

	err := quick.Check(property, &quick.Config{
		MaxCount: 1000,
		Rand:     rand.New(rand.NewSource(18)),
	})
	if err != nil {
		t.Fatal(err)
	}
}

func allowedPasswordCharacters(config PasswordGeneratorConfig) string {
	var characters string
	if config.Uppercase {
		characters += PasswordUppercaseCharacters
	}
	if config.Lowercase {
		characters += PasswordLowercaseCharacters
	}
	if config.Digits {
		characters += PasswordDigits
	}
	if config.Special {
		characters += PasswordSpecialCharacters
	}
	if !config.ExcludeAmbiguous {
		return characters
	}
	return strings.Map(func(character rune) rune {
		if strings.ContainsRune(
			PasswordAmbiguousCharacters,
			character,
		) {
			return -1
		}
		return character
	}, characters)
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
