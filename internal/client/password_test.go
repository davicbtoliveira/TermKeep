package client

import "testing"

func TestValidateMasterPassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{name: "accepts compliant password", password: "TermKeep#2026"},
		{name: "rejects short password", password: "Tk#2026Aa", wantErr: true},
		{name: "rejects password without uppercase", password: "termkeep#2026", wantErr: true},
		{name: "rejects password without lowercase", password: "TERMKEEP#2026", wantErr: true},
		{name: "rejects password without number", password: "TermKeep#safe", wantErr: true},
		{name: "rejects password without special character", password: "TermKeep2026", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateMasterPassword(test.password)
			if (err != nil) != test.wantErr {
				t.Fatalf("ValidateMasterPassword() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}
