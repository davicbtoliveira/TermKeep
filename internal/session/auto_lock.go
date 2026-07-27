package session

import (
	"fmt"
	"strconv"
	"time"
)

const DefaultAutoLock = 15 * time.Minute

// ParseAutoLock converts the user's session preference into an inactivity
// duration. An omitted preference uses the secure default.
func ParseAutoLock(value string) (time.Duration, error) {
	if value == "" {
		return DefaultAutoLock, nil
	}
	if value == "off" {
		return 0, nil
	}
	minutes, err := strconv.Atoi(value)
	if err != nil || minutes < 1 || minutes > 60 {
		return 0, fmt.Errorf("auto-lock must be off or a whole number of minutes from 1 through 60")
	}
	return time.Duration(minutes) * time.Minute, nil
}
