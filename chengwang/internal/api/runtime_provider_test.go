package api

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"chengwang/internal/adapter/mihomo"
)

type scriptedRuntimeReader struct {
	mu        sync.Mutex
	responses []runtimeReaderResponse
}

type runtimeReaderResponse struct {
	snapshot mihomo.RuntimeSnapshot
	err      error
}

func (r *scriptedRuntimeReader) ReadRuntime(context.Context) (mihomo.RuntimeSnapshot, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.responses) == 0 {
		return mihomo.RuntimeSnapshot{}, errors.New("no scripted response")
	}
	next := r.responses[0]
	r.responses = r.responses[1:]
	return next.snapshot, next.err
}

func TestRuntimeProviderMarksFallbackUnreachableAndStale(t *testing.T) {
	reader := &scriptedRuntimeReader{responses: []runtimeReaderResponse{
		{snapshot: mihomo.RuntimeSnapshot{ObservedAt: time.Unix(100, 0).UTC()}},
		{err: errors.New("controller unavailable")},
	}}
	provider := newRuntimeProvider(reader)
	now := time.Unix(100, 0).UTC()
	provider.now = func() time.Time { return now }

	first, err := provider.observe(context.Background(), false)
	if err != nil || !first.Fresh || !first.Reachable || first.Stale {
		t.Fatalf("fresh observation = %+v, err=%v", first, err)
	}
	now = now.Add(provider.ttl + time.Millisecond)
	fallback, err := provider.observe(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if fallback.Fresh || fallback.Reachable || !fallback.Stale || fallback.LastSuccess.IsZero() {
		t.Fatalf("stale fallback = %+v", fallback)
	}
}

func TestRuntimeProviderFailsClosedWhenClockMovesBeforeLastSuccess(t *testing.T) {
	reader := &scriptedRuntimeReader{responses: []runtimeReaderResponse{{snapshot: mihomo.RuntimeSnapshot{}}}}
	provider := newRuntimeProvider(reader)
	now := time.Unix(100, 0).UTC()
	provider.now = func() time.Time { return now }
	if _, err := provider.observe(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	now = time.Unix(99, 0).UTC()
	if _, err := provider.observe(context.Background(), false); !errors.Is(err, errRuntimeClock) {
		t.Fatalf("expected clock error, got %v", err)
	}
}

func TestRuntimeProviderFailsClosedWhenClockMovesDuringRead(t *testing.T) {
	reader := &scriptedRuntimeReader{responses: []runtimeReaderResponse{{snapshot: mihomo.RuntimeSnapshot{ObservedAt: time.Unix(100, 0).UTC()}}}}
	provider := newRuntimeProvider(reader)
	times := []time.Time{time.Unix(100, 0).UTC(), time.Unix(99, 0).UTC()}
	var index int
	provider.now = func() time.Time {
		current := times[index]
		if index < len(times)-1 {
			index++
		}
		return current
	}
	result, err := provider.observe(context.Background(), false)
	if !errors.Is(err, errRuntimeClock) {
		t.Fatalf("expected clock error, got result=%+v err=%v", result, err)
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if provider.hasSnapshot || !provider.lastSuccess.IsZero() || provider.inflight != nil {
		t.Fatalf("clock-invalid result was cached: snapshot=%t success=%s inflight=%v", provider.hasSnapshot, provider.lastSuccess, provider.inflight)
	}
}
