package probe

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSpoolRoundTripLockAndReadLimit(t *testing.T) {
	directory := t.TempDir()
	catalog := testSpoolCatalog(t)
	store, err := OpenStore(directory, catalog, StoreLimits{MaxEntries: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := OpenStore(directory, catalog, StoreLimits{MaxEntries: 4}); !errors.Is(err, ErrSpoolLocked) {
		t.Fatalf("second writer error=%v want ErrSpoolLocked", err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	store.now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if err := store.Append(validTestResult(now.Add(time.Duration(i)*time.Second), string(rune('a'+i)))); err != nil {
			t.Fatal(err)
		}
	}
	report, err := ReadStore(directory, ReadOptions{Catalog: catalog, Limit: 2, Now: now.Add(3 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Healthy || len(report.Results) != 2 || report.Results[0].RunID != "b" || report.Results[1].RunID != "c" {
		t.Fatalf("unexpected read report: %+v", report)
	}
	if _, err := ReadStore(directory, ReadOptions{Catalog: catalog, Limit: 201}); err == nil {
		t.Fatal("expected read limit rejection")
	}
}

func TestSpoolRetentionFailureFreezesWithoutGrowth(t *testing.T) {
	directory := t.TempDir()
	catalog := testSpoolCatalog(t)
	store, err := OpenStore(directory, catalog, StoreLimits{MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().UTC().Truncate(time.Millisecond)
	store.now = func() time.Time { return now }
	if err := store.Append(validTestResult(now, "first")); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadDir(filepath.Join(directory, spoolSegmentsDirectory))
	if err != nil {
		t.Fatal(err)
	}
	store.removeFile = func(string) error { return errors.New("injected delete failure") }
	if err := store.Append(validTestResult(now.Add(time.Second), "second")); err == nil {
		t.Fatal("expected retention failure")
	}
	after, err := os.ReadDir(filepath.Join(directory, spoolSegmentsDirectory))
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != len(after) || len(after) != 1 {
		t.Fatalf("spool grew after cleanup failure: before=%d after=%d", len(before), len(after))
	}
	health := store.Health()
	if health.Writable || health.Healthy || health.Issue != "retention_delete_failed" {
		t.Fatalf("store did not freeze read-only: %+v", health)
	}
	if err := store.Append(validTestResult(now.Add(2*time.Second), "third")); !errors.Is(err, ErrSpoolReadOnly) {
		t.Fatalf("append after freeze error=%v", err)
	}
}

func TestSpoolSuccessfulRetentionRemainsWithinHardEntryLimit(t *testing.T) {
	directory := t.TempDir()
	catalog := testSpoolCatalog(t)
	store, err := OpenStore(directory, catalog, StoreLimits{MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().UTC().Truncate(time.Millisecond)
	store.now = func() time.Time { return now }
	if err := store.Append(validTestResult(now, "first")); err != nil {
		t.Fatal(err)
	}
	if err := store.Append(validTestResult(now.Add(time.Second), "second")); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(directory, spoolSegmentsDirectory))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || store.Health().Entries != 1 || store.Health().ValidResults != 1 {
		t.Fatalf("retention exceeded hard entry limit: disk=%d health=%+v", len(entries), store.Health())
	}
	report, err := ReadStore(directory, ReadOptions{Catalog: catalog, Limit: 1, Now: now.Add(2 * time.Second), MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Results) != 1 || report.Results[0].RunID != "second" {
		t.Fatalf("retention kept wrong result: %+v", report)
	}
}

func TestSpoolUnmanagedEntryConsumesLimitAndBlocksGrowth(t *testing.T) {
	directory := t.TempDir()
	catalog := testSpoolCatalog(t)
	if _, err := secureSpoolDirectory(directory, true); err != nil {
		t.Fatal(err)
	}
	corruptPath := filepath.Join(directory, spoolSegmentsDirectory, "preserve.bin")
	if err := os.WriteFile(corruptPath, []byte("operator evidence"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(directory, catalog, StoreLimits{MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().UTC().Truncate(time.Millisecond)
	store.now = func() time.Time { return now }
	if err := store.Append(validTestResult(now, "blocked")); err == nil {
		t.Fatal("expected unmanaged entry to consume the complete hard limit")
	}
	if health := store.Health(); health.Writable || health.Entries != 1 {
		t.Fatalf("store did not freeze at hard limit: %+v", health)
	}
	entries, err := os.ReadDir(filepath.Join(directory, spoolSegmentsDirectory))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "preserve.bin" {
		t.Fatalf("unmanaged evidence changed: %+v", entries)
	}
}

func TestSpoolCorruptionPreservedAndDegraded(t *testing.T) {
	directory := t.TempDir()
	catalog := testSpoolCatalog(t)
	store, err := OpenStore(directory, catalog, StoreLimits{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	store.now = func() time.Time { return now }
	if err := store.Append(validTestResult(now, "valid")); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	corruptPath := filepath.Join(directory, spoolSegmentsDirectory, "corrupt.json")
	if err := os.WriteFile(corruptPath, []byte(`{"schema":"unknown"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(directory, catalog, StoreLimits{})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if health := reopened.Health(); health.Healthy || health.Issue == "" || !health.Writable {
		t.Fatalf("corruption should degrade but remain bounded-writable: %+v", health)
	}
	if _, err := os.Stat(corruptPath); err != nil {
		t.Fatalf("corrupt evidence was not preserved: %v", err)
	}
	report, err := ReadStore(directory, ReadOptions{Catalog: catalog, Now: now.Add(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	if report.Healthy || report.Rejected != 1 || len(report.Results) != 1 {
		t.Fatalf("unexpected corrupt read report: %+v", report)
	}
}

func TestReaderRejectsUnknownDigestFutureExpiredAndDuplicate(t *testing.T) {
	directory := t.TempDir()
	catalog := testSpoolCatalog(t)
	if _, err := secureSpoolDirectory(directory, true); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	valid := validTestResult(now, "duplicate")
	writeTestSegment(t, directory, valid, "")
	duplicate := valid
	duplicate.CompletedAt = duplicate.CompletedAt.Add(time.Millisecond)
	duplicate.ExpiresAt = duplicate.ExpiresAt.Add(time.Millisecond)
	writeTestSegment(t, directory, duplicate, "")
	future := validTestResult(now.Add(10*time.Minute), "future")
	writeTestSegment(t, directory, future, "")
	expired := validTestResult(now.Add(-11*time.Minute), "expired")
	writeTestSegment(t, directory, expired, "")
	wrongDigest := validTestResult(now, "wrong-digest")
	writeTestSegment(t, directory, wrongDigest, "sha256:"+strings.Repeat("0", 64))
	unknown := validTestResult(now, "unknown-schema")
	segment := makeTestSegment(t, unknown)
	segment.Schema = "chengwang.probe-spool/v999"
	writeRawTestSegment(t, directory, segment, "unknown.json")
	report, err := ReadStore(directory, ReadOptions{Catalog: catalog, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if report.Healthy || len(report.Results) != 1 || report.Rejected != 5 {
		t.Fatalf("unexpected rejection report: %+v", report)
	}
	reasons := map[string]bool{}
	for _, issue := range report.Issues {
		reasons[issue.Reason] = true
	}
	for _, expected := range []string{"duplicate_run_id", "future_result", "expired_result", "content_digest_mismatch", "unknown_schema"} {
		if !reasons[expected] {
			t.Errorf("missing rejection reason %q: %+v", expected, report.Issues)
		}
	}
}

func TestSpoolRejectsIdentityStateAndCatalogMembershipForgery(t *testing.T) {
	directory := t.TempDir()
	catalog := testSpoolCatalog(t)
	store, err := OpenStore(directory, catalog, StoreLimits{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().UTC().Truncate(time.Millisecond)
	store.now = func() time.Time { return now }
	tests := []struct {
		name   string
		mutate func(*ProbeResult)
	}{
		{"NUL identity", func(r *ProbeResult) { r.RunID = "valid\x00collision" }},
		{"unknown probe", func(r *ProbeResult) { r.ProbeID = "unknown-probe" }},
		{"wrong path", func(r *ProbeResult) { r.PathID = "other-path" }},
		{"wrong agent", func(r *ProbeResult) { r.AgentID = "other-agent" }},
		{"wrong independence", func(r *ProbeResult) { r.Independence = IndependenceP2 }},
		{"invalid state pair", func(r *ProbeResult) { r.Outcome = OutcomePass; r.Conclusion = ConclusionUnavailable }},
		{"available with restricted business", func(r *ProbeResult) {
			status := 403
			r.HTTPStatus = &status
			r.ErrorClass = "restricted"
			r.Layers.Business.State = LayerRestricted
			r.Layers.Business.Reason = "access_restricted"
		}},
		{"HTTP evidence without DNS", func(r *ProbeResult) {
			r.Layers.DNS.State = LayerUnavailable
			r.Layers.DNS.Reason = "dns_failure"
		}},
		{"raw degraded conclusion", func(r *ProbeResult) {
			r.Conclusion = ConclusionDegraded
			r.Outcome = OutcomeIndeterminate
			r.Layers.Business.State = LayerDegraded
		}},
		{"complete HTTP response without digest", func(r *ProbeResult) { r.ContentDigest = "" }},
		{"target body budget exceeded", func(r *ProbeResult) { r.ResponseBytes = r.ResponseBytes + 5000 }},
		{"timing budget exceeded", func(r *ProbeResult) { r.StageTimings.TotalMillis = 60_000 }},
		{"retry overflow", func(r *ProbeResult) {
			r.Conclusion = ConclusionRateLimited
			r.Outcome = OutcomeIndeterminate
			r.ErrorClass = "rate_limited"
			status := 429
			r.HTTPStatus = &status
			r.Layers.Business.State = LayerRateLimited
			r.Layers.Business.Reason = "rate_limited"
			r.Layers.Business.RetryAfterSeconds = 9223372036854775807
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := validTestResult(now, "run-"+strings.ReplaceAll(test.name, " ", "-"))
			test.mutate(&result)
			if err := store.Append(result); err == nil {
				t.Fatal("forged result was accepted")
			}
		})
	}
}

func TestReaderRejectsDuplicateJSONKeys(t *testing.T) {
	directory := t.TempDir()
	catalog := testSpoolCatalog(t)
	if _, err := secureSpoolDirectory(directory, true); err != nil {
		t.Fatal(err)
	}
	result := validTestResult(time.Now().UTC().Truncate(time.Millisecond), "duplicate-json")
	segment := makeTestSegment(t, result)
	payload, err := json.Marshal(segment)
	if err != nil {
		t.Fatal(err)
	}
	payload = []byte(strings.Replace(string(payload), `"schema":`, `"schema":"duplicate","schema":`, 1))
	path := filepath.Join(directory, spoolSegmentsDirectory, "duplicate.json")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := ReadStore(directory, ReadOptions{Catalog: catalog, Now: result.CompletedAt})
	if err != nil {
		t.Fatal(err)
	}
	if report.Healthy || report.Rejected != 1 || len(report.Issues) != 1 || report.Issues[0].Reason != "segment_json_duplicate_key" {
		t.Fatalf("duplicate JSON key was not rejected: %+v", report)
	}
}

func TestRunnerHTTPTransportFailureCanBePersisted(t *testing.T) {
	catalog := testSpoolCatalog(t)
	target := catalog.Probes[0]
	attempted := time.Now().UTC().Truncate(time.Millisecond)
	completed := attempted.Add(100 * time.Millisecond)
	result := newUnknownResult(attempted)
	result.RunID = "http-transport-failure"
	result.ProbeID = target.ID
	result.CatalogDigest = catalog.Digest
	result.AgentID = catalog.Agent.ID
	result.Independence = catalog.Agent.Independence
	result.PathID = target.PathID
	result.ExpiresAt = attempted.Add(time.Duration(target.TTLSeconds) * time.Second)
	result.Layers.DNS = layerResult(LayerAvailable, attempted, result.ExpiresAt, 0, "resolved_and_pinned")
	runner := &Runner{now: func() time.Time { return completed }}
	trace := traceSnapshot{
		connectStart: attempted, connectEnd: attempted.Add(10 * time.Millisecond),
		tlsStart: attempted.Add(10 * time.Millisecond), tlsEnd: attempted.Add(20 * time.Millisecond),
		connectDone: true, tlsStarted: true, tlsDone: true,
	}
	result = runner.finishTransportError(result, trace, errors.New("connection reset"), nil)
	if result.Layers.TLS.State != LayerAvailable || result.Layers.HTTP.State != LayerUnavailable {
		t.Fatalf("unexpected transport evidence: %+v", result.Layers)
	}

	store, err := OpenStore(t.TempDir(), catalog, StoreLimits{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	store.now = func() time.Time { return completed }
	if err := store.Append(result); err != nil {
		t.Fatalf("valid runner transport result was rejected: %v", err)
	}
}

func validTestResult(at time.Time, runID string) ProbeResult {
	catalog := validCatalog()
	digest, err := DigestCatalog(catalog)
	if err != nil {
		panic(err)
	}
	target := catalog.Probes[0]
	completed := at.Add(100 * time.Millisecond)
	expires := completed.Add(time.Duration(target.TTLSeconds) * time.Second)
	available := LayerResult{State: LayerAvailable, ObservedAt: completed, ExpiresAt: expires, Reason: "contract_matched"}
	status := 200
	return ProbeResult{
		SchemaVersion: ResultSchemaV1, RunID: runID, ProbeID: target.ID, CatalogDigest: digest,
		AgentID: catalog.Agent.ID, Independence: catalog.Agent.Independence, PathID: target.PathID, AttemptedAt: at,
		CompletedAt: completed, ExpiresAt: expires, Conclusion: ConclusionAvailable,
		Outcome: OutcomePass, HTTPStatus: &status, AdvisoryOnly: true,
		ContentDigest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		Layers:        LayerResults{DNS: available, Connect: available, TLS: available, HTTP: available, Business: available},
	}
}

func makeTestSegment(t *testing.T, result ProbeResult) spoolSegment {
	t.Helper()
	digest, err := spoolContentDigest(SpoolSchemaV1, result.CatalogDigest, result)
	if err != nil {
		t.Fatal(err)
	}
	return spoolSegment{Schema: SpoolSchemaV1, CatalogDigest: result.CatalogDigest, Result: result, Digest: digest}
}

func testSpoolCatalog(t *testing.T) Catalog {
	t.Helper()
	catalog := validCatalog()
	digest, err := DigestCatalog(catalog)
	if err != nil {
		t.Fatal(err)
	}
	catalog.Digest = digest
	return catalog
}

func writeTestSegment(t *testing.T, directory string, result ProbeResult, digestOverride string) {
	t.Helper()
	segment := makeTestSegment(t, result)
	if digestOverride != "" {
		segment.Digest = digestOverride
	}
	writeRawTestSegment(t, directory, segment, spoolSegmentFileName(segment))
}

func writeRawTestSegment(t *testing.T, directory string, segment spoolSegment, name string) {
	t.Helper()
	payload, err := json.Marshal(segment)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, spoolSegmentsDirectory, name), payload, 0o600); err != nil {
		t.Fatal(err)
	}
}
