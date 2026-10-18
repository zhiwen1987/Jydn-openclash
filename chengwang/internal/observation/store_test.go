package observation

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStorePersistsAndTrimsOldestSamples(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenStore(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	base := time.Date(2026, 10, 18, 1, 2, 3, 0, time.UTC)
	for i := 1; i <= 3; i++ {
		sample := Sample{Sequence: uint64(i), AttemptedAt: base.Add(time.Duration(i) * time.Minute), CompletedAt: base.Add(time.Duration(i)*time.Minute + time.Second), DurationMillis: 1000, Success: true}
		if err := store.Append(sample); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	samples := reopened.List(10)
	if len(samples) != 2 || samples[0].Sequence != 2 || samples[1].Sequence != 3 {
		t.Fatalf("unexpected retained samples: %+v", samples)
	}
}

func TestStorePreservesCorruptSegmentAndStartsDegraded(t *testing.T) {
	dir := t.TempDir()
	sampleDir := filepath.Join(dir, storeDirectoryName)
	if err := os.MkdirAll(sampleDir, 0o700); err != nil {
		t.Fatal(err)
	}
	corrupt := filepath.Join(sampleDir, "00000000000000000001-00000000000000000001.json")
	if err := os.WriteFile(corrupt, []byte(`{"version":1,"sample":{},"unexpected":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(dir, 2)
	if err != nil {
		t.Fatalf("corrupt non-critical telemetry blocked startup: %v", err)
	}
	defer store.Close()
	if healthy, issue := store.Healthy(); healthy || issue != "corrupt_segment" {
		t.Fatalf("corruption not surfaced: healthy=%t issue=%q", healthy, issue)
	}
	if _, err := os.Stat(corrupt); err != nil {
		t.Fatalf("corrupt evidence was not preserved: %v", err)
	}
}

func TestStoreRejectsOutOfOrderAndRawFailureWithoutClass(t *testing.T) {
	store, err := OpenStore(t.TempDir(), 2)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().UTC()
	if err := store.Append(Sample{Sequence: 1, AttemptedAt: now, CompletedAt: now, Success: false}); err == nil {
		t.Fatal("expected missing error class to fail")
	}
	if err := store.Append(Sample{Sequence: 1, AttemptedAt: now, CompletedAt: now, Success: false, ErrorClass: "token=leak"}); err == nil {
		t.Fatal("expected arbitrary error class to fail")
	}
	if err := store.Append(Sample{Sequence: 1, AttemptedAt: now, CompletedAt: now, Success: true, ControllerVersion: strings.Repeat("v", 129)}); err == nil {
		t.Fatal("expected oversized controller version to fail")
	}
	if err := store.Append(Sample{Sequence: 2, AttemptedAt: now, CompletedAt: now, Success: true}); err != nil {
		t.Fatal(err)
	}
	if err := store.Append(Sample{Sequence: 1, AttemptedAt: now.Add(time.Second), CompletedAt: now.Add(time.Second), Success: true}); err == nil {
		t.Fatal("expected sequence rollback to fail")
	}
}

func TestStoreRejectsSecondWriterUntilClose(t *testing.T) {
	dir := t.TempDir()
	first, err := OpenStore(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(dir, 2); !errors.Is(err, ErrStoreLocked) {
		t.Fatalf("second writer error = %v, want ErrStoreLocked", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := OpenStore(dir, 2)
	if err != nil {
		t.Fatalf("lock not released: %v", err)
	}
	defer second.Close()
}

func TestStoreDeleteFailureStopsWritesWithoutGrowth(t *testing.T) {
	store, err := OpenStore(t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	base := time.Date(2026, 10, 18, 1, 2, 3, 0, time.UTC)
	first := Sample{Sequence: 1, AttemptedAt: base, CompletedAt: base.Add(time.Second), DurationMillis: 1000, Success: true}
	second := Sample{Sequence: 2, AttemptedAt: base.Add(time.Minute), CompletedAt: base.Add(time.Minute + time.Second), DurationMillis: 1000, Success: true}
	if err := store.Append(first); err != nil {
		t.Fatal(err)
	}
	store.removeFile = func(string) error { return errors.New("injected delete failure") }
	if err := store.Append(second); err == nil {
		t.Fatal("expected retention delete failure")
	}
	if err := store.Append(second); !errors.Is(err, ErrStoreReadOnly) {
		t.Fatalf("degraded store accepted another write: %v", err)
	}
	entries, err := os.ReadDir(store.sampleDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || len(store.List(10)) != 1 || store.List(10)[0].Sequence != 1 {
		t.Fatalf("delete failure expanded store: entries=%d samples=%+v", len(entries), store.List(10))
	}
}

func TestStoreStartupRecoversExcessSegmentsDeterministically(t *testing.T) {
	dir := t.TempDir()
	sampleDir := filepath.Join(dir, storeDirectoryName)
	if err := os.MkdirAll(sampleDir, 0o700); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 10, 18, 1, 2, 3, 0, time.UTC)
	for i := 1; i <= 4; i++ {
		sample := Sample{Sequence: uint64(i), AttemptedAt: base.Add(time.Duration(i) * time.Minute), CompletedAt: base.Add(time.Duration(i)*time.Minute + time.Second), DurationMillis: 1000, Success: true}
		committed, err := writeSampleAtomically(sampleDir, filepath.Join(sampleDir, sampleFileName(sample)), sample)
		if err != nil || !committed {
			t.Fatalf("seed segment %d: committed=%t err=%v", i, committed, err)
		}
	}
	store, err := OpenStore(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	samples := store.List(10)
	if len(samples) != 2 || samples[0].Sequence != 3 || samples[1].Sequence != 4 {
		t.Fatalf("startup did not retain newest samples: %+v", samples)
	}
	entries, err := os.ReadDir(sampleDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("startup recovery left %d segments, want 2", len(entries))
	}
	if healthy, issue := store.Healthy(); !healthy || issue != "" {
		t.Fatalf("successful recovery remained degraded: healthy=%t issue=%q", healthy, issue)
	}
}

func TestLoadSegmentsBoundsAllDirectoryEntriesAndDisablesWrites(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 5; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("junk-%d.tmp", i)), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_, _, healthy, issue, writable, err := loadSegments(dir, 2, 4)
	if err != nil {
		t.Fatal(err)
	}
	if healthy || issue != "unexpected_directory_entry" || writable {
		t.Fatalf("unexpected bounded scan result: healthy=%t issue=%q writable=%t", healthy, issue, writable)
	}
}
