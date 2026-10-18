package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"chengwang/internal/probe"
)

func TestHealthFileRoundTripAndCommand(t *testing.T) {
	directory := privateHealthDirectory(t)
	catalog, catalogPath := writeHealthTestCatalog(t, directory)
	healthPath := filepath.Join(directory, "probe-agent.json")
	now := time.Now().UTC().Truncate(time.Millisecond)
	record := healthyRecord(catalog.Digest, now)
	if err := writeHealthFile(healthPath, record); err != nil {
		t.Fatalf("writeHealthFile() first error = %v", err)
	}
	record.Started = 2
	record.Completed = 1
	if err := writeHealthFile(healthPath, record); err != nil {
		t.Fatalf("writeHealthFile() replacement error = %v", err)
	}
	if err := runHealthCommand([]string{
		"--health-file", healthPath, "--catalog", catalogPath, "--max-age", "30s",
	}, &bytes.Buffer{}, func() time.Time { return now.Add(time.Second) }); err != nil {
		t.Fatalf("runHealthCommand() error = %v", err)
	}
	if err := execute(context.Background(), []string{
		"health", "--health-file", healthPath, "--catalog", catalogPath, "--max-age", "30s",
	}, &bytes.Buffer{}); err != nil {
		t.Fatalf("execute(health) error = %v", err)
	}
	read, err := readHealthFile(healthPath)
	if err != nil {
		t.Fatalf("readHealthFile() error = %v", err)
	}
	if read != record {
		t.Fatalf("health record = %+v, want %+v", read, record)
	}
	raw, err := os.ReadFile(healthPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, prohibited := range []string{"dns", "internet", "canary", "node", "business", "target"} {
		if strings.Contains(strings.ToLower(string(raw)), prohibited) {
			t.Fatalf("health record leaked prohibited concept %q: %s", prohibited, raw)
		}
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(healthPath)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("health mode = %o, want 600", info.Mode().Perm())
		}
	}
}

func TestHealthCommandRejectsInvalidEvidence(t *testing.T) {
	directory := privateHealthDirectory(t)
	catalog, catalogPath := writeHealthTestCatalog(t, directory)
	healthPath := filepath.Join(directory, "probe-agent.json")
	now := time.Date(2026, 10, 18, 2, 3, 4, 0, time.UTC)

	tests := []struct {
		name   string
		mutate func(*probeAgentHealth)
		want   string
	}{
		{"future", func(record *probeAgentHealth) { record.UpdatedAt = now.Add(healthFutureSkew + time.Nanosecond) }, "future"},
		{"stale", func(record *probeAgentHealth) { record.UpdatedAt = now.Add(-31 * time.Second) }, "stale"},
		{"schema", func(record *probeAgentHealth) { record.Schema = "chengwang.probe-agent-health/v2" }, "schema"},
		{"digest format", func(record *probeAgentHealth) { record.CatalogDigest = "sha256:no" }, "digest"},
		{"digest mismatch", func(record *probeAgentHealth) { record.CatalogDigest = "sha256:" + strings.Repeat("0", 64) }, "digest"},
		{"not running", func(record *probeAgentHealth) { record.Running = false }, "unhealthy"},
		{"clock", func(record *probeAgentHealth) { record.ClockHealthy = false }, "unhealthy"},
		{"storage", func(record *probeAgentHealth) { record.StorageHealthy = false }, "unhealthy"},
		{"not advisory", func(record *probeAgentHealth) { record.AdvisoryOnly = false }, "mode"},
		{"not active", func(record *probeAgentHealth) { record.ActiveProbes = false }, "mode"},
		{"queued bound", func(record *probeAgentHealth) { record.Queued = probe.DefaultProbeQueueSize + 1 }, "bounded"},
		{"active bound", func(record *probeAgentHealth) { record.Active = 17 }, "bounded"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record := healthyRecord(catalog.Digest, now)
			test.mutate(&record)
			writeRawHealthRecord(t, healthPath, record)
			err := runHealthCommand([]string{"--health-file", healthPath, "--catalog", catalogPath, "--max-age", "30s"}, nil, func() time.Time { return now })
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("runHealthCommand() error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestHealthReaderRejectsMalformedUnsafeAndOversizedFiles(t *testing.T) {
	directory := privateHealthDirectory(t)
	catalog, _ := writeHealthTestCatalog(t, directory)
	healthPath := filepath.Join(directory, "probe-agent.json")
	now := time.Now().UTC()
	record := healthyRecord(catalog.Digest, now)
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("unknown field", func(t *testing.T) {
		withUnknown := append(bytes.TrimSuffix(raw, []byte("}")), []byte(`,"internetHealthy":true}`)...)
		if err := os.WriteFile(healthPath, withUnknown, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readHealthFile(healthPath); err == nil || !strings.Contains(err.Error(), "unknown field") {
			t.Fatalf("readHealthFile() error = %v", err)
		}
	})

	t.Run("duplicate field", func(t *testing.T) {
		duplicate := append(bytes.TrimSuffix(raw, []byte("}")), []byte(`,"running":true}`)...)
		if err := os.WriteFile(healthPath, duplicate, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readHealthFile(healthPath); err == nil || !strings.Contains(err.Error(), "duplicate") {
			t.Fatalf("readHealthFile() error = %v", err)
		}
	})

	t.Run("trailing value", func(t *testing.T) {
		if err := os.WriteFile(healthPath, append(raw, []byte("\n{}")...), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readHealthFile(healthPath); err == nil || !strings.Contains(err.Error(), "trailing") {
			t.Fatalf("readHealthFile() error = %v", err)
		}
	})

	t.Run("oversized", func(t *testing.T) {
		if err := os.WriteFile(healthPath, bytes.Repeat([]byte{'x'}, int(maximumHealthFileBytes+1)), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readHealthFile(healthPath); err == nil || !strings.Contains(err.Error(), "size") {
			t.Fatalf("readHealthFile() error = %v", err)
		}
	})

	t.Run("symlink", func(t *testing.T) {
		target := filepath.Join(directory, "target.json")
		writeRawHealthRecord(t, target, record)
		_ = os.Remove(healthPath)
		if err := os.Symlink(target, healthPath); err != nil {
			t.Skipf("symbolic links unavailable: %v", err)
		}
		if _, err := readHealthFile(healthPath); err == nil || !strings.Contains(err.Error(), "symbolic link") {
			t.Fatalf("readHealthFile() error = %v", err)
		}
	})
}

func TestHealthPermissionsAreFailClosed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no portable Unix permission-bit contract")
	}
	parent := t.TempDir()
	insecureDirectory := filepath.Join(parent, "health")
	if err := os.Mkdir(insecureDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := validateHealthFileLocation(filepath.Join(insecureDirectory, "health.json")); err == nil || !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("validateHealthFileLocation() error = %v", err)
	}

	secureDirectory := filepath.Join(parent, "private")
	if err := os.Mkdir(secureDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	healthPath := filepath.Join(secureDirectory, "health.json")
	if err := os.WriteFile(healthPath, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := validateExistingHealthFile(healthPath); err == nil || !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("validateExistingHealthFile() error = %v", err)
	}
}

func TestHealthReaderRejectsHardLinkedFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no portable Unix hard-link metadata contract")
	}
	directory := privateHealthDirectory(t)
	catalog, _ := writeHealthTestCatalog(t, directory)
	healthPath := filepath.Join(directory, "health.json")
	writeRawHealthRecord(t, healthPath, healthyRecord(catalog.Digest, time.Now().UTC()))
	if err := os.Link(healthPath, filepath.Join(directory, "alias.json")); err != nil {
		t.Fatalf("create hard link: %v", err)
	}
	if _, err := readHealthFile(healthPath); err == nil || !strings.Contains(err.Error(), "hard link") {
		t.Fatalf("readHealthFile() error = %v, want hard-link rejection", err)
	}
}

func TestHealthCommandArgumentsAreStrictAndDirectRunRemainsCompatible(t *testing.T) {
	directory := privateHealthDirectory(t)
	_, catalogPath := writeHealthTestCatalog(t, directory)
	healthPath := filepath.Join(directory, "health.json")
	tests := []struct {
		args []string
		want string
	}{
		{[]string{"--catalog", catalogPath}, "health --health-file is required"},
		{[]string{"--health-file", healthPath}, "health --catalog is required"},
		{[]string{"--health-file", healthPath, "--health-file", healthPath, "--catalog", catalogPath}, "duplicate"},
		{[]string{"--health-file", healthPath, "--catalog", catalogPath, "positional"}, "only named --flag"},
		{[]string{"--health-file", healthPath, "--catalog", catalogPath, "--unknown", "value"}, "flag provided but not defined"},
		{[]string{"--health-file", healthPath, "--catalog", catalogPath, "--max-age", "999s"}, "between"},
	}
	for _, test := range tests {
		if err := runHealthCommand(test.args, nil, time.Now); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Fatalf("runHealthCommand(%v) error = %v, want containing %q", test.args, err, test.want)
		}
	}

	directArgs := append(validArguments(directory), "--health-file", healthPath)
	parsed, err := parseConfig(directArgs, nil)
	if err != nil {
		t.Fatalf("direct run parseConfig() error = %v", err)
	}
	if parsed.healthFilePath != healthPath {
		t.Fatalf("direct run health path = %q", parsed.healthFilePath)
	}
}

func TestHealthPublisherEmitsStatusAndStopsOnCancellation(t *testing.T) {
	now := time.Now().UTC()
	status := probe.SchedulerStatus{
		Running: true, ClockHealthy: true, StorageHealthy: true,
		Queued: 2, Active: 1, Started: 4, Completed: 3, Canceled: 1,
		BudgetSkipped: 5, QueueSkipped: 6, SinkFailures: 7,
	}
	var mu sync.Mutex
	var records []probeAgentHealth
	publisher := &healthPublisher{
		path: "unused", catalogDigest: "sha256:" + strings.Repeat("a", 64),
		status: func() probe.SchedulerStatus { return status }, now: func() time.Time { return now },
		interval: 5 * time.Millisecond,
		write: func(_ string, record probeAgentHealth) error {
			mu.Lock()
			records = append(records, record)
			mu.Unlock()
			return nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- publisher.run(ctx) }()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		count := len(records)
		mu.Unlock()
		if count >= 2 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("healthPublisher.run() error = %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(records) < 2 {
		t.Fatalf("published records = %d, want at least 2", len(records))
	}
	if got := records[0]; got.CatalogDigest != publisher.catalogDigest || !got.Running || !got.AdvisoryOnly || !got.ActiveProbes || got.SinkFailures != 7 {
		t.Fatalf("published health = %+v", got)
	}
}

func TestHealthPublisherPropagatesWriteFailure(t *testing.T) {
	want := errors.New("tmpfs full")
	publisher := &healthPublisher{
		path: "unused", catalogDigest: "sha256:" + strings.Repeat("a", 64),
		status: func() probe.SchedulerStatus {
			return probe.SchedulerStatus{Running: true, ClockHealthy: true, StorageHealthy: true}
		},
		now: time.Now, interval: time.Second,
		write: func(string, probeAgentHealth) error { return want },
	}
	if err := publisher.run(context.Background()); !errors.Is(err, want) {
		t.Fatalf("healthPublisher.run() error = %v", err)
	}
}

func healthyRecord(digest string, updatedAt time.Time) probeAgentHealth {
	return probeAgentHealth{
		Schema: probeAgentHealthSchema, State: probeAgentHealthState, UpdatedAt: updatedAt,
		CatalogDigest: digest, Running: true, ClockHealthy: true, StorageHealthy: true,
		AdvisoryOnly: true, ActiveProbes: true,
	}
}

func privateHealthDirectory(t *testing.T) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "health")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func writeHealthTestCatalog(t *testing.T, directory string) (probe.Catalog, string) {
	t.Helper()
	catalog := commandTestCatalog(t)
	raw, err := json.Marshal(catalog)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "catalog.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return catalog, path
}

func writeRawHealthRecord(t *testing.T, path string, record probeAgentHealth) {
	t.Helper()
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}
