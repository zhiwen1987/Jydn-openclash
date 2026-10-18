package observation

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"chengwang/internal/adapter/mihomo"
)

type fakeReader struct {
	snapshot mihomo.RuntimeSnapshot
	err      error
}

func (f *fakeReader) ReadRuntime(context.Context) (mihomo.RuntimeSnapshot, error) {
	return f.snapshot, f.err
}

func TestCollectorSeparatesControllerEvidenceFromUnmeasuredLayers(t *testing.T) {
	store, err := OpenStore(t.TempDir(), 10)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	base := time.Date(2026, 10, 18, 2, 0, 0, 0, time.UTC)
	reader := &fakeReader{snapshot: mihomo.RuntimeSnapshot{
		Version: mihomo.VersionInfo{Version: "v1"},
		Proxies: []mihomo.ProxyState{{Name: "group", Type: "Selector"}, {Name: "secret-node", Type: "VLESS"}},
		Rules:   []mihomo.RuleState{{Type: "MATCH"}},
	}}
	collector, err := NewCollector(reader, store, 10*time.Second, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	clock := base
	collector.now = func() time.Time { current := clock; clock = clock.Add(time.Second); return current }
	collector.collect(context.Background())
	status := collector.Status()
	if !status.Fresh || status.Controller.State != StateAvailable {
		t.Fatalf("controller evidence not fresh: %+v", status)
	}
	if status.NodeTechnical.State != StateUnknown || status.Internet.State != StateUnknown || status.Business.State != StateUnknown || status.DNS.State != StateUnknown {
		t.Fatalf("unmeasured layer was inferred: %+v", status)
	}
	detail := collector.Detail(10)
	if len(detail.Samples) != 1 || detail.Samples[0].SelectorGroupCount != 1 || detail.Samples[0].LeafProxyCount != 1 {
		t.Fatalf("unexpected passive sample: %+v", detail)
	}
	if got := string(mustMarshal(t, detail)); contains(got, "secret-node") {
		t.Fatalf("node name leaked into observation history: %s", got)
	}
}

func TestCollectorFailureClassIsBoundedAndExpiresOldSuccess(t *testing.T) {
	store, err := OpenStore(t.TempDir(), 10)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	base := time.Date(2026, 10, 18, 2, 0, 0, 0, time.UTC)
	reader := &fakeReader{snapshot: mihomo.RuntimeSnapshot{}}
	collector, err := NewCollector(reader, store, 10*time.Second, 20*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	now := base
	collector.now = func() time.Time { return now }
	collector.collect(context.Background())
	reader.err = errors.New("token=do-not-leak")
	now = base.Add(30 * time.Second)
	collector.collect(context.Background())
	status := collector.Status()
	if !status.Stale || status.Controller.State != StateDegraded || status.ConsecutiveFailures != 1 {
		t.Fatalf("stale evidence misclassified: %+v", status)
	}
	samples := collector.Detail(10).Samples
	if samples[len(samples)-1].ErrorClass != "read_failed" || contains(string(mustMarshal(t, samples)), "do-not-leak") {
		t.Fatalf("raw error leaked: %+v", samples)
	}
}

func TestCollectorClockRollbackFailsClosedWithoutCallingUpstream(t *testing.T) {
	store, err := OpenStore(t.TempDir(), 10)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	reader := &countingReader{}
	collector, err := NewCollector(reader, store, 10*time.Second, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 10, 18, 3, 0, 0, 0, time.UTC)
	now := base
	collector.now = func() time.Time { return now }
	collector.collect(context.Background())
	now = base.Add(-time.Minute)
	collector.collect(context.Background())
	status := collector.Status()
	if status.Clock.State != StateUnavailable || status.Controller.State != StateUnknown || status.Fresh || reader.calls != 1 {
		t.Fatalf("clock rollback did not fail closed: calls=%d status=%+v", reader.calls, status)
	}
}

func TestCollectorRestartDoesNotRefreshFutureEvidence(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenStore(dir, 10)
	if err != nil {
		t.Fatal(err)
	}
	future := time.Date(2026, 10, 18, 5, 0, 0, 0, time.UTC)
	if err := store.Append(Sample{Sequence: 1, AttemptedAt: future, CompletedAt: future.Add(time.Second), DurationMillis: 1000, Success: true}); err != nil {
		t.Fatal(err)
	}
	collector, err := NewCollector(&fakeReader{}, store, 10*time.Second, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	collector.now = func() time.Time { return future.Add(-time.Minute) }
	status := collector.Status()
	if status.Fresh || status.Controller.State != StateUnknown || status.Clock.State != StateUnavailable {
		t.Fatalf("future evidence was refreshed by restart: %+v", status)
	}
	_ = store.Close()
}

func TestCollectorShutdownCancellationDoesNotCreateFailureSample(t *testing.T) {
	store, err := OpenStore(t.TempDir(), 10)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	collector, err := NewCollector(cancelReader{}, store, 10*time.Second, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	collector.collect(ctx)
	if samples := store.List(10); len(samples) != 0 {
		t.Fatalf("shutdown cancellation created failure history: %+v", samples)
	}
	if status := collector.Status(); status.ConsecutiveFailures != 0 {
		t.Fatalf("shutdown cancellation created a failure: %+v", status)
	}
}

type cancelReader struct{}

func (cancelReader) ReadRuntime(ctx context.Context) (mihomo.RuntimeSnapshot, error) {
	return mihomo.RuntimeSnapshot{}, ctx.Err()
}

type countingReader struct{ calls int }

func (r *countingReader) ReadRuntime(context.Context) (mihomo.RuntimeSnapshot, error) {
	r.calls++
	return mihomo.RuntimeSnapshot{}, nil
}

type concurrencyReader struct {
	active int32
	peak   int32
	gate   chan struct{}
}

func (r *concurrencyReader) ReadRuntime(ctx context.Context) (mihomo.RuntimeSnapshot, error) {
	active := atomic.AddInt32(&r.active, 1)
	for {
		peak := atomic.LoadInt32(&r.peak)
		if active <= peak || atomic.CompareAndSwapInt32(&r.peak, peak, active) {
			break
		}
	}
	defer atomic.AddInt32(&r.active, -1)
	select {
	case <-r.gate:
		return mihomo.RuntimeSnapshot{}, nil
	case <-ctx.Done():
		return mihomo.RuntimeSnapshot{}, ctx.Err()
	}
}

func TestSerializedReaderAllowsOnlyOneUpstreamCallAtATime(t *testing.T) {
	raw := &concurrencyReader{gate: make(chan struct{})}
	reader, err := NewSerializedReader(raw)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = reader.ReadRuntime(context.Background()) }()
	}
	for i := 0; i < 10; i++ {
		raw.gate <- struct{}{}
	}
	wg.Wait()
	if peak := atomic.LoadInt32(&raw.peak); peak != 1 {
		t.Fatalf("upstream concurrency = %d, want 1", peak)
	}
}
