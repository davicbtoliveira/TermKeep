package client

import (
	"crypto/rand"
	"errors"
	"math/big"
)

var ErrInvalidPasswordGeneratorConfig = errors.New(
	"invalid password generator configuration",
)

const PasswordUppercaseCharacters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
const PasswordLowercaseCharacters = "abcdefghijklmnopqrstuvwxyz"
const PasswordDigits = "0123456789"
const PasswordSpecialCharacters = "!@#$%^&*()-_=+[]{};:,.?/|"
const PasswordAmbiguousCharacters = "Il1O0o|"

type PasswordGeneratorConfig struct {
	Length           int
	Uppercase        bool
	Lowercase        bool
	Digits           bool
	Special          bool
	MinimumDigits    int
	MinimumSpecial   int
	ExcludeAmbiguous bool
}

func ValidatePasswordGeneratorConfig(
	config PasswordGeneratorConfig,
) error {
	if config.Length < 5 ||
		config.Length > 128 ||
		config.MinimumDigits < 0 ||
		config.MinimumSpecial < 0 ||
		(config.MinimumDigits > 0 && !config.Digits) ||
		(config.MinimumSpecial > 0 && !config.Special) ||
		config.MinimumDigits+config.MinimumSpecial > config.Length ||
		passwordCharacterSet(config) == "" {
		return ErrInvalidPasswordGeneratorConfig
	}
	return nil
}

func GeneratePassword(
	config PasswordGeneratorConfig,
) (string, error) {
	if err := ValidatePasswordGeneratorConfig(config); err != nil {
		return "", err
	}
	allowed := passwordCharacterSet(config)
	password := make([]byte, 0, config.Length)
	for range config.MinimumDigits {
		character, err := randomPasswordCharacter(PasswordDigits)
		if err != nil {
			return "", err
		}
		password = append(password, character)
	}
	for range config.MinimumSpecial {
		character, err := randomPasswordCharacter(
			PasswordSpecialCharacters,
		)
		if err != nil {
			return "", err
		}
		password = append(password, character)
	}
	for len(password) < config.Length {
		character, err := randomPasswordCharacter(allowed)
		if err != nil {
			return "", err
		}
		password = append(password, character)
	}
	for index := len(password) - 1; index > 0; index-- {
		swap, err := randomPasswordIndex(index + 1)
		if err != nil {
			return "", err
		}
		password[index], password[swap] = password[swap], password[index]
	}
	return string(password), nil
}

func passwordCharacterSet(config PasswordGeneratorConfig) string {
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
	return characters
}

func randomPasswordCharacter(characters string) (byte, error) {
	index, err := randomPasswordIndex(len(characters))
	if err != nil {
		return 0, err
	}
	return characters[index], nil
}

func randomPasswordIndex(limit int) (int, error) {
	value, err := rand.Int(rand.Reader, big.NewInt(int64(limit)))
	if err != nil {
		return 0, err
	}
	return int(value.Int64()), nil
}
