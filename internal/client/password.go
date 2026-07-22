package client

import (
	"errors"
	"unicode"
	"unicode/utf8"
)

var ErrWeakMasterPassword = errors.New("master password must contain at least 12 characters, uppercase, lowercase, number, and special character")

// ValidateMasterPassword enforces TermKeep's master-password policy before
// any password-derived material leaves the client.
func ValidateMasterPassword(password string) error {
	if utf8.RuneCountInString(password) < 12 {
		return ErrWeakMasterPassword
	}

	var upper, lower, number, special bool
	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsLower(r):
			lower = true
		case unicode.IsNumber(r):
			number = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			special = true
		}
	}

	if !upper || !lower || !number || !special {
		return ErrWeakMasterPassword
	}
	return nil
}
