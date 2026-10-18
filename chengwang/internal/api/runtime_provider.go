package api

import (
	"context"
	"errors"
	"sync"
	"time"

	"chengwang/internal/adapter/mihomo"
)

var errRuntimeBusy = errors.New("mihomo runtime refresh admission is full")
var errRuntimeClock = errors.New("mihomo runtime clock moved backwards")

const (
	defaultRuntimeTTL      = 5 * time.Second
	defaultRuntimeMaxStale = 30 * time.Second
	maxRuntimeWaiters      = 16
)

type runtimeObservation struct {
	Snapshot    mihomo.RuntimeSnapshot
	Fresh       bool
	Reachable   bool
	Stale       bool
	LastSuccess time.Time
}

// runtimeProvider is a single-key cache and single-flight boundary for the
// controller. It deliberately never caches by caller-supplied drafts: readback
// compares drafts locally against this one bounded runtime snapshot.
type runtimeProvider struct {
	reader   MihomoReader
	ttl      time.Duration
	maxStale time.Duration
	now      func() time.Time

	mu          sync.Mutex
	snapshot    mihomo.RuntimeSnapshot
	hasSnapshot bool
	lastSuccess time.Time
	lastAttempt time.Time
	inflight    chan struct{}
	waiters     int
}

func newRuntimeProvider(reader MihomoReader) *runtimeProvider {
	if reader == nil {
		return nil
	}
	return &runtimeProvider{
		reader: reader, ttl: defaultRuntimeTTL, maxStale: defaultRuntimeMaxStale,
		now: time.Now,
	}
}

func (p *runtimeProvider) observe(ctx context.Context, requireFresh bool) (runtimeObservation, error) {
	for {
		p.mu.Lock()
		// Sample the admission clock while holding the same mutex that protects
		// lastAttempt and lastSuccess. Sampling before Lock lets an older sample
		// wait behind a newer request and then look like a wall-clock rollback.
		now := p.now().UTC()
		if (p.hasSnapshot && now.Before(p.lastSuccess)) || (!p.lastAttempt.IsZero() && now.Before(p.lastAttempt)) {
			p.mu.Unlock()
			return runtimeObservation{}, errRuntimeClock
		}
		if p.hasSnapshot && now.Sub(p.lastSuccess) <= p.ttl {
			result := p.observationLocked(true, true)
			p.mu.Unlock()
			return result, nil
		}
		if p.inflight != nil {
			if p.waiters >= maxRuntimeWaiters {
				p.mu.Unlock()
				return runtimeObservation{}, errRuntimeBusy
			}
			wait := p.inflight
			p.waiters++
			p.mu.Unlock()
			select {
			case <-ctx.Done():
				p.mu.Lock()
				p.waiters--
				p.mu.Unlock()
				return runtimeObservation{}, ctx.Err()
			case <-wait:
				p.mu.Lock()
				p.waiters--
				p.mu.Unlock()
				continue
			}
		}
		// A failed controller must not be hammered on every request. During the
		// TTL backoff window, serve an explicitly stale bounded snapshot only
		// where the caller allows it.
		if !p.lastAttempt.IsZero() && now.Sub(p.lastAttempt) < p.ttl {
			if !requireFresh && p.hasSnapshot && now.Sub(p.lastSuccess) <= p.maxStale {
				result := p.observationLocked(false, false)
				p.mu.Unlock()
				return result, nil
			}
			p.mu.Unlock()
			return runtimeObservation{}, errRuntimeBusy
		}
		p.lastAttempt = now
		p.inflight = make(chan struct{})
		done := p.inflight
		p.mu.Unlock()

		snapshot, err := p.reader.ReadRuntime(ctx)
		p.mu.Lock()
		completedAt := p.now().UTC()
		if completedAt.Before(p.lastAttempt) || (p.hasSnapshot && completedAt.Before(p.lastSuccess)) {
			p.inflight = nil
			close(done)
			p.mu.Unlock()
			return runtimeObservation{}, errRuntimeClock
		}
		if err == nil {
			p.snapshot = snapshot
			p.hasSnapshot = true
			p.lastSuccess = completedAt
		}
		p.inflight = nil
		close(done)
		if err != nil && !requireFresh && p.hasSnapshot && completedAt.Sub(p.lastSuccess) <= p.maxStale {
			result := p.observationLocked(false, false)
			p.mu.Unlock()
			return result, nil
		}
		if err != nil {
			p.mu.Unlock()
			return runtimeObservation{}, err
		}
		result := p.observationLocked(true, true)
		p.mu.Unlock()
		return result, nil
	}
}

func (p *runtimeProvider) observationLocked(fresh, reachable bool) runtimeObservation {
	return runtimeObservation{
		Snapshot: p.snapshot, Fresh: fresh, Reachable: reachable,
		Stale: !fresh && p.hasSnapshot, LastSuccess: p.lastSuccess,
	}
}
