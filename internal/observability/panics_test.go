package observability

import (
	"log/slog"
	"os"
	"testing"
	"time"
)

func TestPanicHandlerCrashLoop(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	handler := &PanicHandler{
		panicCounts: make(map[string][]time.Time),
	}

	component := "test-comp"

	// Trigger 4 panics rapidly
	for i := 0; i < 4; i++ {
		disabled := handler.HandlePanic(component, "fake panic", logger)
		if disabled {
			t.Fatalf("expected component to NOT be disabled on panic %d", i+1)
		}
	}

	// 5th panic should disable it
	disabled := handler.HandlePanic(component, "fake panic", logger)
	if !disabled {
		t.Fatalf("expected component to BE disabled on panic 5")
	}
}
