package session_test

import (
	"testing"
	"time"

	"github.com/davicbtoliveira/TermKeep/internal/session"
)

func TestAutoLockDefaultsToFifteenMinutes(t *testing.T) {
	got, err := session.ParseAutoLock("")
	if err != nil {
		t.Fatal(err)
	}
	if got != 15*time.Minute {
		t.Fatalf("default auto-lock: want 15m, got %s", got)
	}
}

func TestAutoLockCanBeDisabled(t *testing.T) {
	got, err := session.ParseAutoLock("off")
	if err != nil {
		t.Fatal(err)
	}
	if got != 0 {
		t.Fatalf("disabled auto-lock: want 0, got %s", got)
	}
}

func TestAutoLockAcceptsOneThroughSixtyMinutes(t *testing.T) {
	for value, want := range map[string]time.Duration{
		"1":  time.Minute,
		"60": time.Hour,
	} {
		got, err := session.ParseAutoLock(value)
		if err != nil {
			t.Errorf("ParseAutoLock(%q): %v", value, err)
			continue
		}
		if got != want {
			t.Errorf("ParseAutoLock(%q): want %s, got %s", value, want, got)
		}
	}
}

func TestAutoLockRejectsValuesOutsideOneThroughSixtyMinutes(t *testing.T) {
	for _, value := range []string{"0", "61", "-1", "15m", "disabled"} {
		if _, err := session.ParseAutoLock(value); err == nil {
			t.Errorf("ParseAutoLock(%q): want error", value)
		}
	}
}
