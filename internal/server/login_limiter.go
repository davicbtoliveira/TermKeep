package server

import (
	"sync"
	"time"
)

const loginFailureReset = 24 * time.Hour

type loginAttemptKey struct {
	account string
	source  string
}

type loginAttempt struct {
	failures   int
	lastFailed time.Time
}

// LoginLimiter applies temporary delays independently per account and
// network origin.
type LoginLimiter struct {
	mu       sync.Mutex
	now      func() time.Time
	attempts map[loginAttemptKey]loginAttempt
}

func NewLoginLimiter(now func() time.Time) *LoginLimiter {
	return &LoginLimiter{
		now:      now,
		attempts: make(map[loginAttemptKey]loginAttempt),
	}
}

func (l *LoginLimiter) RecordFailure(account, source string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	key := loginAttemptKey{account: account, source: source}
	attempt := l.attempts[key]
	now := l.now()
	if !attempt.lastFailed.IsZero() && now.Sub(attempt.lastFailed) >= loginFailureReset {
		attempt.failures = 0
	}
	attempt.failures++
	attempt.lastFailed = now
	l.attempts[key] = attempt
}

func (l *LoginLimiter) RetryAfter(account, source string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	key := loginAttemptKey{account: account, source: source}
	attempt := l.attempts[key]
	if attempt.failures < 5 {
		return 0
	}
	delay := time.Minute
	switch attempt.failures {
	case 6:
		delay = 5 * time.Minute
	case 7:
		delay = 10 * time.Minute
	default:
		if attempt.failures >= 8 {
			delay = 15 * time.Minute
		}
	}
	remaining := attempt.lastFailed.Add(delay).Sub(l.now())
	if remaining <= 0 {
		return 0
	}
	return remaining
}

func (l *LoginLimiter) Reset(account, source string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.attempts, loginAttemptKey{account: account, source: source})
}
