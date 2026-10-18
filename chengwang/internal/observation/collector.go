package observation

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"chengwang/internal/adapter/mihomo"
)

type RuntimeReader interface {
	ReadRuntime(context.Context) (mihomo.RuntimeSnapshot, error)
}

// SerializedReader prevents a background observation and an interactive
// readback from multiplying Controller load. Waiting callers remain bounded by
// their contexts and no extra goroutine is created per queued request.
type SerializedReader struct {
	source RuntimeReader
	gate   chan struct{}
}

func NewSerializedReader(source RuntimeReader) (*SerializedReader, error) {
	if source == nil {
		return nil, errors.New("serialized observation reader source is required")
	}
	return &SerializedReader{source: source, gate: make(chan struct{}, 1)}, nil
}

func (r *SerializedReader) ReadRuntime(ctx context.Context) (mihomo.RuntimeSnapshot, error) {
	select {
	case r.gate <- struct{}{}:
		defer func() { <-r.gate }()
	case <-ctx.Done():
		return mihomo.RuntimeSnapshot{}, ctx.Err()
	}
	return r.source.ReadRuntime(ctx)
}

type Collector struct {
	reader   RuntimeReader
	store    *Store
	interval time.Duration
	ttl      time.Duration
	now      func() time.Time

	mu                  sync.RWMutex
	running             bool
	sequence            uint64
	lastAttempt         time.Time
	lastCompleted       time.Time
	lastSuccess         time.Time
	consecutiveFailures int
	storageHealthy      bool
	clockHealthy        bool
	refreshMu           sync.Mutex
}

func NewCollector(reader RuntimeReader, store *Store, interval, ttl time.Duration) (*Collector, error) {
	if reader == nil || store == nil {
		return nil, errors.New("observation reader and store are required")
	}
	if interval < 10*time.Second || interval > 10*time.Minute {
		return nil, errors.New("observation interval must be between 10s and 10m")
	}
	if ttl < interval || ttl > 30*time.Minute {
		return nil, errors.New("observation TTL must be at least the interval and no more than 30m")
	}
	storageHealthy, _ := store.Healthy()
	c := &Collector{reader: reader, store: store, interval: interval, ttl: ttl, now: time.Now, storageHealthy: storageHealthy, clockHealthy: true}
	if last, ok := store.Last(); ok {
		c.sequence = last.Sequence
		c.lastAttempt = last.AttemptedAt
		c.lastCompleted = last.CompletedAt
		for _, sample := range reverse(store.List(0)) {
			if sample.Success {
				c.lastSuccess = sample.CompletedAt
				break
			}
			c.consecutiveFailures++
		}
	}
	return c, nil
}

func (c *Collector) Run(ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		close(done)
		return done
	}
	c.running = true
	c.mu.Unlock()
	go func() {
		defer close(done)
		defer func() { c.mu.Lock(); c.running = false; c.mu.Unlock() }()
		c.collect(ctx)
		ticker := time.NewTicker(c.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.collect(ctx)
			}
		}
	}()
	return done
}

func (c *Collector) collect(ctx context.Context) {
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()
	attempted := c.now().UTC()
	c.mu.Lock()
	if !c.lastCompleted.IsZero() && attempted.Before(c.lastCompleted) {
		c.clockHealthy = false
		c.consecutiveFailures++
		c.mu.Unlock()
		return
	}
	c.mu.Unlock()
	snapshot, err := c.reader.ReadRuntime(ctx)
	if errors.Is(err, context.Canceled) && ctx.Err() != nil {
		return
	}
	completed := c.now().UTC()
	if completed.Before(attempted) || (!c.lastCompleted.IsZero() && completed.Before(c.lastCompleted)) {
		c.mu.Lock()
		c.clockHealthy = false
		c.lastAttempt = attempted
		c.consecutiveFailures++
		c.mu.Unlock()
		return
	}
	duration := completed.Sub(attempted).Milliseconds()
	if duration < 0 {
		duration = 0
	}
	c.mu.Lock()
	c.clockHealthy = true
	c.sequence++
	sample := Sample{Sequence: c.sequence, AttemptedAt: attempted, CompletedAt: completed, DurationMillis: duration}
	if err == nil {
		sample.Success = true
		sample.ControllerVersion = truncate(snapshot.Version.Version, 128)
		sample.ProxyObjectCount = len(snapshot.Proxies)
		sample.RuleCount = len(snapshot.Rules)
		for _, proxy := range snapshot.Proxies {
			if isSelector(proxy.Type) {
				sample.SelectorGroupCount++
			} else {
				sample.LeafProxyCount++
			}
		}
	} else {
		sample.ErrorClass = classifyError(err)
	}
	c.lastAttempt = attempted
	c.lastCompleted = completed
	if sample.Success {
		c.lastSuccess = completed
		c.consecutiveFailures = 0
	} else {
		c.consecutiveFailures++
	}
	c.mu.Unlock()
	// A persistence failure must not turn a failed observation into a success.
	// The HTTP summary will continue to expose freshness from memory, while the
	// protected history remains the durable source of individual samples.
	persistErr := c.store.Append(sample)
	storeHealthy, _ := c.store.Healthy()
	c.mu.Lock()
	c.storageHealthy = persistErr == nil && storeHealthy
	c.mu.Unlock()
}

func (c *Collector) Status() Status {
	now := c.now().UTC()
	c.mu.RLock()
	lastAttempt, lastCompleted, lastSuccess := c.lastAttempt, c.lastCompleted, c.lastSuccess
	failures, running, storageHealthy, clockHealthy := c.consecutiveFailures, c.running, c.storageHealthy, c.clockHealthy
	c.mu.RUnlock()
	fresh := clockHealthy && !lastSuccess.IsZero() && now.Sub(lastSuccess) <= c.ttl && failures == 0
	stale := !lastSuccess.IsZero() && !fresh
	controller := Layer{State: StateUnknown, Reason: "尚无控制器观测证据"}
	if fresh {
		controller = layerWithTimes(StateAvailable, lastSuccess, lastSuccess.Add(c.ttl), "Mihomo Controller 周期读回成功")
	} else if stale {
		reason := "最近成功证据已过期"
		if failures > 0 {
			reason = "最近一次控制器读回失败，仅保留之前的成功证据"
		}
		controller = layerWithTimes(StateDegraded, lastSuccess, lastSuccess.Add(c.ttl), reason)
	} else if !lastAttempt.IsZero() && failures > 0 {
		controller = layerWithTimes(StateUnavailable, lastAttempt, lastAttempt.Add(c.ttl), "控制器周期读回失败")
	}
	unknown := func(reason string) Layer { return Layer{State: StateUnknown, Reason: reason} }
	storage := Layer{State: StateAvailable, Reason: "观测摘要持久化正常"}
	if !lastAttempt.IsZero() {
		storage.ObservedAt = timePointer(lastAttempt)
	}
	if !storageHealthy {
		storage = Layer{State: StateDegraded, ObservedAt: timePointer(lastAttempt), Reason: "最近观测摘要持久化失败"}
	}
	clock := Layer{State: StateAvailable, Reason: "观测时钟单调性正常"}
	if !clockHealthy || (!lastAttempt.IsZero() && now.Before(lastAttempt)) || (!lastCompleted.IsZero() && now.Before(lastCompleted)) || (!lastSuccess.IsZero() && now.Before(lastSuccess)) {
		clock = Layer{State: StateUnavailable, Reason: "检测到时钟回拨，当前观测结论不可用于协调"}
		controller = Layer{State: StateUnknown, Reason: "时钟不可信，控制器观测结论已冻结"}
		fresh = false
		stale = !lastSuccess.IsZero()
	}
	return Status{
		Configured: true, Mode: "passive_read_only", Running: running, Fresh: fresh, Stale: stale,
		LastAttemptAt: optionalTime(lastAttempt), LastSuccessAt: optionalTime(lastSuccess), ConsecutiveFailures: failures,
		Controller:    controller,
		NodeTechnical: unknown("尚未启用独立节点技术探针，不能由控制器可达推断"),
		Internet:      unknown("尚未启用端到端互联网探针"),
		Business:      unknown("尚未启用按业务定义的许可清单探针"),
		DNS:           unknown("尚未启用 DNS 路径与泄漏探针"),
		Storage:       storage,
		Clock:         clock,
	}
}

func layerWithTimes(state State, observedAt, expiresAt time.Time, reason string) Layer {
	return Layer{State: state, ObservedAt: timePointer(observedAt), ExpiresAt: timePointer(expiresAt), Reason: reason}
}

func optionalTime(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	return timePointer(value)
}

func timePointer(value time.Time) *time.Time {
	value = value.UTC()
	return &value
}

func (c *Collector) Detail(limit int) Detail {
	if limit <= 0 || limit > 200 {
		limit = 200
	}
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()
	return Detail{Status: c.Status(), Samples: c.store.List(limit)}
}

func classifyError(err error) string {
	var upstream *mihomo.HTTPError
	var netErr net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.As(err, &upstream) && (upstream.StatusCode == http.StatusUnauthorized || upstream.StatusCode == http.StatusForbidden):
		return "authentication"
	case errors.As(err, &upstream):
		return "upstream_http"
	case errors.As(err, &netErr):
		return "network"
	default:
		return "read_failed"
	}
}

func isSelector(proxyType string) bool {
	switch strings.ToLower(strings.TrimSpace(proxyType)) {
	case "selector", "urltest", "fallback", "loadbalance", "relay":
		return true
	default:
		return false
	}
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}

func reverse(samples []Sample) []Sample {
	result := make([]Sample, len(samples))
	for i := range samples {
		result[len(samples)-1-i] = samples[i]
	}
	return result
}
