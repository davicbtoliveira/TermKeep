package clipboard_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/davicbtoliveira/TermKeep/internal/clipboard"
)

func TestCopyClearsUnchangedClipboardAfterDelay(t *testing.T) {
	board := &memoryClipboard{}

	cleanup, err := clipboard.Copy(
		context.Background(),
		board,
		"Password-Sentinel",
		time.Millisecond,
	)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-cleanup:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("clipboard cleanup timed out")
	}
	if value, clears := board.snapshot(); value != "" || clears != 1 {
		t.Fatalf("clipboard after cleanup: value %q, clears %d", value, clears)
	}
}

type memoryClipboard struct {
	mu     sync.Mutex
	value  string
	clears int
}

func (board *memoryClipboard) Write(_ context.Context, value string) error {
	board.mu.Lock()
	defer board.mu.Unlock()
	board.value = value
	return nil
}

func (board *memoryClipboard) Read(context.Context) (string, error) {
	board.mu.Lock()
	defer board.mu.Unlock()
	return board.value, nil
}

func (board *memoryClipboard) Clear(context.Context) error {
	board.mu.Lock()
	defer board.mu.Unlock()
	board.value = ""
	board.clears++
	return nil
}

func (board *memoryClipboard) snapshot() (string, int) {
	board.mu.Lock()
	defer board.mu.Unlock()
	return board.value, board.clears
}
