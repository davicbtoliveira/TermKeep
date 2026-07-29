package clipboard

import (
	"context"
	"errors"
	"time"
)

const ClearDelay = 30 * time.Second

var ErrUnavailable = errors.New("clipboard unavailable")

type Backend interface {
	Write(ctx context.Context, value string) error
	Read(ctx context.Context) (string, error)
	Clear(ctx context.Context) error
}

func Open() (Backend, error) {
	return nil, ErrUnavailable
}

func Copy(
	ctx context.Context,
	backend Backend,
	value string,
	clearAfter time.Duration,
) (<-chan error, error) {
	if err := backend.Write(ctx, value); err != nil {
		return nil, err
	}
	cleanup := make(chan error, 1)
	go func() {
		timer := time.NewTimer(clearAfter)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			cleanup <- ctx.Err()
		case <-timer.C:
			current, err := backend.Read(context.Background())
			if err == nil && current == value {
				err = backend.Clear(context.Background())
			}
			cleanup <- err
		}
		close(cleanup)
	}()
	return cleanup, nil
}
