//go:build linux

package mihomodeploy

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"chengwang/internal/adapter/mihomo"
)

// Structural timing/denial tests only. They never issue a native Started
// registry item, fabricate a live observation, call HTTP or alter globals.
// Genuine S1 custody and successful consumption need the native acceptance.
func TestLabRecoveryCollectorAbsoluteWindowRejectsFutureStaleAndReordering(t *testing.T) {
	entry := time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC)
	times := [2]mihomo.LabSampleTimes{
		{StartedAt: entry.Add(time.Millisecond), CompletedAt: entry.Add(2 * time.Millisecond)},
		{StartedAt: entry.Add(3 * time.Millisecond), CompletedAt: entry.Add(4 * time.Millisecond)},
	}
	observed, deadline := entry.Add(5*time.Millisecond), entry.Add(10*time.Second)
	if !labRecoveryObservationWindow(times, entry, observed, deadline) {
		t.Fatal("actual ordered time values rejected")
	}
	for _, name := range []string{"before-entry", "negative-round", "overlap", "future-completion", "zero", "at-deadline", "rollback"} {
		t.Run(name, func(t *testing.T) {
			changed, end := times, observed
			switch name {
			case "before-entry":
				changed[0].StartedAt = entry.Add(-time.Nanosecond)
			case "negative-round":
				changed[0].CompletedAt = changed[0].StartedAt.Add(-time.Nanosecond)
			case "overlap":
				changed[1].StartedAt = changed[0].CompletedAt.Add(-time.Nanosecond)
			case "future-completion":
				changed[1].CompletedAt = end.Add(time.Nanosecond)
			case "zero":
				changed[1].CompletedAt = time.Time{}
			case "at-deadline":
				end = deadline
			case "rollback":
				end = entry.Add(-time.Nanosecond)
			}
			if labRecoveryObservationWindow(changed, entry, end, deadline) {
				t.Fatal("absolute window admitted " + name)
			}
		})
	}
}

func TestLabRecoveryCollectorSourceDeadlineUsesAllSixBounds(t *testing.T) {
	entry := time.Now().UTC()
	bounds := [4]time.Time{entry.Add(time.Hour), entry.Add(time.Hour), entry.Add(time.Hour), entry.Add(time.Hour)}
	actual, ok := labRecoveryWindowDeadline(entry, 10000, bounds, context.Background())
	if !ok || !actual.Equal(entry.Add(10*time.Second)) {
		t.Fatal("fixed budget did not bound the attempt")
	}
	for n := range bounds {
		changed := bounds
		changed[n] = entry.Add(time.Second)
		actual, ok := labRecoveryWindowDeadline(entry, 10000, changed, context.Background())
		if !ok || !actual.Equal(changed[n]) {
			t.Fatal("source expiry/Started bound lost")
		}
		changed[n] = entry
		if _, ok := labRecoveryWindowDeadline(entry, 10000, changed, context.Background()); ok {
			t.Fatal("expired source admitted")
		}
	}
	ctx, cancel := context.WithDeadline(context.Background(), entry.Add(2*time.Second))
	defer cancel()
	actual, ok = labRecoveryWindowDeadline(entry, 10000, bounds, ctx)
	if !ok || !actual.Equal(entry.Add(2*time.Second)) {
		t.Fatal("caller deadline was extended")
	}
	cancel()
	if _, ok := labRecoveryWindowDeadline(entry, 10000, bounds, ctx); ok {
		t.Fatal("cancelled caller admitted")
	}
	if _, ok := labRecoveryWindowDeadline(entry, 10001, bounds, context.Background()); ok {
		t.Fatal("caller expanded fixed budget")
	}
}

func TestLabRecoveryCollectorModelS1CannotMintNativeCustody(t *testing.T) {
	for _, mode := range []string{"committed", "failed-publication", "unknown-publication"} {
		t.Run(mode, func(t *testing.T) {
			s, disk, owner, q, now := lifecycleStartedRecordModel(t)
			if mode == "failed-publication" {
				disk.state = lifecycleNotCommitted
			}
			if mode == "unknown-publication" {
				disk.state = lifecycleUnknown
			}
			err := s.recordRecoveryStarted(owner, q, now)
			if (mode == "committed") != (err == nil) {
				t.Fatal("MODEL publication control did not reach expected branch")
			}
			if s.core.retainedStarted != nil {
				t.Fatal("MODEL issuer minted native observation custody")
			}
			prior := bytes.Clone(disk.raw)
			coreCopy := *q.core
			for _, replay := range []*labRecoveryStartedEpoch{q, &labRecoveryStartedEpoch{core: &coreCopy}} {
				if s.recordRecoveryStarted(owner, replay, now) == nil || s.core.retainedStarted != nil || !bytes.Equal(prior, disk.raw) {
					t.Fatal("spent original/copy restored custody or changed WAL")
				}
			}
			if mode == "committed" {
				reopened, err := openLifecycleRecoveryStore(&lifecycleModelDisk{raw: bytes.Clone(disk.raw), exists: true, state: lifecycleCommitted}, now)
				if err != nil || reopened.core.retainedStarted != nil {
					t.Fatal("reopen inherited ephemeral native custody")
				}
				_ = reopened.close()
			}
			_ = s.close()
		})
	}
}

func TestLabRecoveryCollectorEntryAndSerializedEvidenceReject(t *testing.T) {
	if _, err := newLabRecoveryCollector(nil, nil, nil, nil); err == nil {
		t.Fatal("nil custody inputs admitted")
	}
	var collector *labRecoveryCollector
	if _, err := collector.collect(context.Background(), nil); err == nil {
		t.Fatal("nil collector admitted")
	}
	if value, err := collector.consume(context.Background(), nil, nil); err == nil || !reflect.DeepEqual(value, labRecoveryObservedValue{}) {
		t.Fatal("nil evidence returned facts")
	}
	var evidence labRecoveryObservedEvidence
	if json.Unmarshal([]byte(`{"schema":"fake","core":{}}`), &evidence) == nil || evidence.core != nil {
		t.Fatal("JSON constructed evidence")
	}
	if _, err := json.Marshal(evidence); err == nil {
		t.Fatal("private evidence serialized as authority")
	}
	var custody labRecoveryStartedCustody
	if json.Unmarshal([]byte(`{"started":{}}`), &custody) == nil {
		t.Fatal("JSON constructed Started custody")
	}
	if custody.matches(nil) {
		t.Fatal("unissued private metadata matched")
	}
}

func TestLabRecoveryCollectorCaptureNamesStayClosed(t *testing.T) {
	for _, name := range []string{"recovery-s2/transcript.json", "recovery-s2/body-1.json", "recovery-s2/body-8.json", "recovery-s2/verification.json"} {
		if !labDiagnosticName(name) {
			t.Fatal("fixed source capture unavailable")
		}
	}
	for _, name := range []string{"recovery-s2/body-0.json", "recovery-s2/body-9.json", "recovery-s2/../verification.json", "recovery-s2/custom.json", "recovery-s2/sub/body-1.json", "recovery-s3/transcript.json"} {
		if labDiagnosticName(name) {
			t.Fatal("capture path widened")
		}
	}
	if !labDiagnosticName("op-01/post-dispatch/transcript.json") || !labDiagnosticName("bootstrap/body-1.json") {
		t.Fatal("original capture paths changed")
	}
}
