package clipboard

import (
	"context"
	"time"
)

const ClearDelay = 30 * time.Second

type Backend interface {
	Write(ctx context.Context, value string) error
	Read(ctx context.Context) (string, error)
	Clear(ctx context.Context) error
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
			cleanup <- backend.Clear(context.Background())
		}
		close(cleanup)
	}()
	return cleanup, nil
}
