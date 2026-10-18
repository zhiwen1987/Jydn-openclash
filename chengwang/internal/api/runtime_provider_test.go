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
