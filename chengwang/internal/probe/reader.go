package probe

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

var spoolIdentityPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

const (
	SpoolSchemaV1            = "chengwang.probe-spool/v1"
	DefaultSpoolMaxEntries   = 4096
	DefaultSpoolMaxBytes     = int64(64 << 20)
	MaximumSpoolSegmentBytes = int64(64 << 10)
	MaximumReadResults       = 200
	defaultReadResults       = 100
	defaultFutureSkew        = 2 * time.Minute
	spoolSegmentsDirectory   = "segments"
)

type spoolSegment struct {
	Schema        string      `json:"schema"`
	CatalogDigest string      `json:"catalogDigest"`
	Result        ProbeResult `json:"result"`
	Digest        string      `json:"digest"`
}

type spoolDigestPayload struct {
	Schema        string      `json:"schema"`
	CatalogDigest string      `json:"catalogDigest"`
	Result        ProbeResult `json:"result"`
}

type ReadOptions struct {
	Catalog       Catalog
	Limit         int
	Now           time.Time
	MaxFutureSkew time.Duration
	MaxEntries    int
	MaxBytes      int64
}

type catalogBinding struct {
	digest       string
	agentID      string
	independence IndependenceLevel
	targets      map[string]Target
}

func bindCatalog(catalog Catalog) (catalogBinding, error) {
	digest, err := DigestCatalog(catalog)
	if err != nil {
		return catalogBinding{}, err
	}
	if catalog.Digest == "" || catalog.Digest != digest {
		return catalogBinding{}, errors.New("catalog digest is missing or does not match its contents")
	}
	binding := catalogBinding{digest: digest, agentID: catalog.Agent.ID, independence: catalog.Agent.Independence, targets: make(map[string]Target, len(catalog.Probes))}
	for _, target := range catalog.Probes {
		binding.targets[target.ID] = target
	}
	return binding, nil
}

type ReadIssue struct {
	File   string `json:"file"`
	Reason string `json:"reason"`
}

type ReadReport struct {
	Results      []ProbeResult `json:"results"`
	Healthy      bool          `json:"healthy"`
	Issue        string        `json:"issue,omitempty"`
	Rejected     int           `json:"rejected"`
	TotalEntries int           `json:"totalEntries"`
	TotalBytes   int64         `json:"totalBytes"`
	Issues       []ReadIssue   `json:"issues,omitempty"`
}

type spoolMeta struct {
	name   string
	size   int64
	result ProbeResult
}

type spoolScan struct {
	valid        []spoolMeta
	issues       []ReadIssue
	totalEntries int
	totalBytes   int64
}

// ReadStore imports a bounded verified view without acquiring the writer lock
// or changing any spool file. Unknown schemas, modified content, wrong catalog
// generations, future/expired samples, and duplicate run IDs are excluded.
func ReadStore(directory string, options ReadOptions) (ReadReport, error) {
	if options.Limit == 0 {
		options.Limit = defaultReadResults
	}
	if options.Limit < 1 || options.Limit > MaximumReadResults {
		return ReadReport{}, fmt.Errorf("probe read limit must be between 1 and %d", MaximumReadResults)
	}
	if options.Now.IsZero() {
		options.Now = time.Now()
	}
	if options.MaxFutureSkew == 0 {
		options.MaxFutureSkew = defaultFutureSkew
	}
	if options.MaxFutureSkew < 0 || options.MaxFutureSkew > 10*time.Minute {
		return ReadReport{}, errors.New("probe future skew must be between zero and ten minutes")
	}
	maxEntries, maxBytes, err := normalizeSpoolLimits(options.MaxEntries, options.MaxBytes)
	if err != nil {
		return ReadReport{}, err
	}
	binding, err := bindCatalog(options.Catalog)
	if err != nil {
		return ReadReport{}, fmt.Errorf("bind probe catalog: %w", err)
	}
	absDirectory, err := secureSpoolDirectory(directory, false)
	if err != nil {
		return ReadReport{}, err
	}
	scan, err := scanSpoolSegments(filepath.Join(absDirectory, spoolSegmentsDirectory), binding, options.Now, options.MaxFutureSkew, true, maxEntries, maxBytes)
	if err != nil {
		return ReadReport{}, err
	}
	results := make([]ProbeResult, 0, min(options.Limit, len(scan.valid)))
	start := len(scan.valid) - options.Limit
	if start < 0 {
		start = 0
	}
	for _, meta := range scan.valid[start:] {
		results = append(results, meta.result)
	}
	report := ReadReport{
		Results: results, Healthy: len(scan.issues) == 0,
		Rejected: len(scan.issues), TotalEntries: scan.totalEntries, TotalBytes: scan.totalBytes,
		Issues: append([]ReadIssue(nil), scan.issues...),
	}
	if len(scan.issues) > 0 {
		report.Issue = scan.issues[0].Reason
	}
	return report, nil
}

func scanSpoolSegments(directory string, binding catalogBinding, now time.Time, futureSkew time.Duration, temporal bool, maxEntries int, maxBytes int64) (spoolScan, error) {
	dir, err := os.Open(directory)
	if err != nil {
		return spoolScan{}, fmt.Errorf("open probe spool segments: %w", err)
	}
	defer dir.Close()
	scan := spoolScan{}
	allEntries := make([]os.DirEntry, 0, min(maxEntries+1, DefaultSpoolMaxEntries+1))
	for {
		entries, readErr := dir.ReadDir(128)
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return spoolScan{}, fmt.Errorf("list probe spool segments: %w", readErr)
		}
		allEntries = append(allEntries, entries...)
		if len(allEntries) > DefaultSpoolMaxEntries {
			scan.totalEntries = len(allEntries)
			scan.issues = append(scan.issues, ReadIssue{Reason: "absolute_directory_entry_limit"})
			return scan, nil
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
	}
	sort.Slice(allEntries, func(i, j int) bool { return allEntries[i].Name() < allEntries[j].Name() })
	scan.totalEntries = len(allEntries)
	if scan.totalEntries > maxEntries {
		scan.issues = append(scan.issues, ReadIssue{Reason: "directory_entry_limit"})
		return scan, nil
	}
	for _, entry := range allEntries {
		info, infoErr := entry.Info()
		if infoErr != nil {
			scan.issues = append(scan.issues, ReadIssue{File: entry.Name(), Reason: "entry_inspection_failed"})
			continue
		}
		if info.Size() < 0 || info.Size() > maxBytes-scan.totalBytes {
			scan.totalBytes = maxBytes + 1
			scan.issues = append(scan.issues, ReadIssue{File: entry.Name(), Reason: "directory_byte_limit"})
			break
		}
		if info.Size() > 0 {
			scan.totalBytes += info.Size()
		}
	}
	if scan.totalBytes > maxBytes {
		scan.issues = append(scan.issues, ReadIssue{Reason: "directory_byte_limit"})
		return scan, nil
	}
	seenRuns := make(map[string]struct{})
	for _, entry := range allEntries {
		info, infoErr := entry.Info()
		if infoErr != nil {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || !strings.HasSuffix(entry.Name(), ".json") {
			scan.issues = append(scan.issues, ReadIssue{File: entry.Name(), Reason: "unexpected_directory_entry"})
			continue
		}
		segment, reason := readSpoolSegment(filepath.Join(directory, entry.Name()), binding, now, futureSkew, temporal)
		if reason != "" {
			scan.issues = append(scan.issues, ReadIssue{File: entry.Name(), Reason: reason})
			continue
		}
		if entry.Name() != spoolSegmentFileName(segment) {
			scan.issues = append(scan.issues, ReadIssue{File: entry.Name(), Reason: "filename_mismatch"})
			continue
		}
		if _, duplicate := seenRuns[segment.Result.RunID]; duplicate {
			scan.issues = append(scan.issues, ReadIssue{File: entry.Name(), Reason: "duplicate_run_id"})
			continue
		}
		seenRuns[segment.Result.RunID] = struct{}{}
		scan.valid = append(scan.valid, spoolMeta{name: entry.Name(), size: info.Size(), result: segment.Result})
	}
	sort.Slice(scan.valid, func(i, j int) bool {
		if scan.valid[i].result.CompletedAt.Equal(scan.valid[j].result.CompletedAt) {
			return scan.valid[i].name < scan.valid[j].name
		}
		return scan.valid[i].result.CompletedAt.Before(scan.valid[j].result.CompletedAt)
	})
	return scan, nil
}

func readSpoolSegment(path string, binding catalogBinding, now time.Time, futureSkew time.Duration, temporal bool) (spoolSegment, string) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return spoolSegment{}, "segment_not_regular"
	}
	if info.Size() <= 0 || info.Size() > MaximumSpoolSegmentBytes {
		return spoolSegment{}, "segment_size_invalid"
	}
	file, err := os.Open(path)
	if err != nil {
		return spoolSegment{}, "segment_open_failed"
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return spoolSegment{}, "segment_identity_changed"
	}
	payload, err := io.ReadAll(io.LimitReader(file, MaximumSpoolSegmentBytes+1))
	if err != nil || int64(len(payload)) > MaximumSpoolSegmentBytes {
		return spoolSegment{}, "segment_read_failed"
	}
	if err := rejectDuplicateJSONKeys(payload); err != nil {
		return spoolSegment{}, "segment_json_duplicate_key"
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var segment spoolSegment
	if err := decoder.Decode(&segment); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return spoolSegment{}, "segment_json_invalid"
	}
	if segment.Schema != SpoolSchemaV1 {
		return spoolSegment{}, "unknown_schema"
	}
	if segment.CatalogDigest != binding.digest || segment.Result.CatalogDigest != binding.digest {
		return spoolSegment{}, "catalog_digest_mismatch"
	}
	expectedDigest, err := spoolContentDigest(segment.Schema, segment.CatalogDigest, segment.Result)
	if err != nil || segment.Digest != expectedDigest {
		return spoolSegment{}, "content_digest_mismatch"
	}
	if reason := validateSpoolResult(segment.Result, binding, now, futureSkew, temporal); reason != "" {
		return spoolSegment{}, reason
	}
	return segment, ""
}

func validateSpoolResult(result ProbeResult, binding catalogBinding, now time.Time, futureSkew time.Duration, temporal bool) string {
	if result.SchemaVersion != ResultSchemaV1 {
		return "unknown_result_schema"
	}
	if !spoolIdentityPattern.MatchString(result.RunID) || !idPattern.MatchString(result.ProbeID) || !idPattern.MatchString(result.AgentID) || !idPattern.MatchString(result.PathID) {
		return "result_identity_invalid"
	}
	if result.CatalogDigest != binding.digest || !validSpoolCatalogDigest(result.CatalogDigest) {
		return "catalog_digest_mismatch"
	}
	target, targetKnown := binding.targets[result.ProbeID]
	if !targetKnown || result.AgentID != binding.agentID || result.Independence != binding.independence || target.PathID != result.PathID {
		return "catalog_membership_mismatch"
	}
	if !result.AdvisoryOnly {
		return "result_not_advisory"
	}
	if result.AttemptedAt.IsZero() || result.AttemptedAt.UnixNano() < 0 || result.CompletedAt.Before(result.AttemptedAt) || !result.ExpiresAt.After(result.CompletedAt) || result.ExpiresAt.Sub(result.CompletedAt) > 2*time.Hour {
		return "result_time_invalid"
	}
	expectedTTL := time.Duration(target.TTLSeconds) * time.Second
	if result.ExpiresAt.Sub(result.CompletedAt) != expectedTTL || result.CompletedAt.Sub(result.AttemptedAt) > time.Duration(target.TimeoutSeconds+1)*time.Second {
		return "result_contract_time_invalid"
	}
	maxTiming := int64(target.TimeoutSeconds+1) * 1000
	if result.ResponseBytes < 0 || result.ResponseBytes > target.MaxBodyBytes || result.StageTimings.DNSMillis < 0 || result.StageTimings.ConnectMillis < 0 || result.StageTimings.TLSMillis < 0 || result.StageTimings.HTTPMillis < 0 || result.StageTimings.TotalMillis < 0 || result.StageTimings.DNSMillis > maxTiming || result.StageTimings.ConnectMillis > maxTiming || result.StageTimings.TLSMillis > maxTiming || result.StageTimings.HTTPMillis > maxTiming || result.StageTimings.TotalMillis > maxTiming {
		return "result_value_invalid"
	}
	if result.Independence != IndependenceP1 || !validSpoolStatePair(result.Conclusion, result.Outcome) {
		return "result_enum_invalid"
	}
	if result.ContentDigest != "" && !validSpoolCatalogDigest(result.ContentDigest) {
		return "content_digest_invalid"
	}
	if result.EvidenceRef != "" && !spoolIdentityPattern.MatchString(result.EvidenceRef) {
		return "evidence_ref_invalid"
	}
	if !validProbeErrorClass(result.ErrorClass) || !validLayerResults(result, target) || !validLayerDependencies(result) || !validResultSemantics(result, target) {
		return "result_layer_invalid"
	}
	if result.HTTPStatus != nil && (*result.HTTPStatus < 100 || *result.HTTPStatus > 599) {
		return "result_http_status_invalid"
	}
	if temporal {
		futureBoundary := now.Add(futureSkew)
		if result.AttemptedAt.After(futureBoundary) || result.CompletedAt.After(futureBoundary) {
			return "future_result"
		}
		if !result.ExpiresAt.After(now) {
			return "expired_result"
		}
	}
	return ""
}

func validResultSemantics(result ProbeResult, target Target) bool {
	business := result.Layers.Business.State
	switch result.Conclusion {
	case ConclusionAvailable:
		return result.Outcome == OutcomePass && result.ErrorClass == "" && business == LayerAvailable && result.HTTPStatus != nil && *result.HTTPStatus >= 200 && *result.HTTPStatus <= 299 && containsStatus(target.ExpectedStatus, *result.HTTPStatus) && result.Layers.DNS.State == LayerAvailable && reachedHTTP(result)
	case ConclusionRestricted:
		return result.Outcome == OutcomeIndeterminate && result.ErrorClass == "restricted" && business == LayerRestricted && result.HTTPStatus != nil && (*result.HTTPStatus == 401 || *result.HTTPStatus == 403) && result.Layers.Business.RetryAfterSeconds == 0 && result.ContentDigest != "" && reachedHTTP(result)
	case ConclusionRateLimited:
		return result.Outcome == OutcomeIndeterminate && result.ErrorClass == "rate_limited" && business == LayerRateLimited && result.HTTPStatus != nil && *result.HTTPStatus == 429 && result.ContentDigest != "" && reachedHTTP(result)
	case ConclusionUnavailable:
		if result.Outcome != OutcomeFail || business != LayerUnknown || result.HTTPStatus != nil || result.ResponseBytes != 0 {
			return false
		}
		return result.Layers.DNS.State == LayerUnavailable || result.Layers.Connect.State == LayerUnavailable || result.Layers.TLS.State == LayerUnavailable || result.Layers.HTTP.State == LayerUnavailable
	case ConclusionUnknown:
		if result.Outcome != OutcomeIndeterminate || (business != LayerUnknown && business != LayerDegraded) || result.Layers.Business.RetryAfterSeconds != 0 {
			return false
		}
		return result.HTTPStatus == nil || reachedHTTPOrDegradedBody(result)
	}
	return false
}

func reachedHTTP(result ProbeResult) bool {
	return result.Layers.DNS.State == LayerAvailable && result.Layers.Connect.State == LayerAvailable && result.Layers.TLS.State == LayerAvailable && result.Layers.HTTP.State == LayerAvailable
}

func reachedHTTPOrDegradedBody(result ProbeResult) bool {
	return result.Layers.DNS.State == LayerAvailable && result.Layers.Connect.State == LayerAvailable && result.Layers.TLS.State == LayerAvailable && (result.Layers.HTTP.State == LayerAvailable || result.Layers.HTTP.State == LayerDegraded)
}

// validLayerDependencies rejects impossible evidence chains. ResolveAndRun
// always performs these stages in order, so a downstream observed stage must
// have every prerequisite available. This prevents a forged 403/429 from
// claiming success after an unavailable DNS, TCP, or TLS stage.
func validLayerDependencies(result ProbeResult) bool {
	dns := result.Layers.DNS.State
	connect := result.Layers.Connect.State
	tlsState := result.Layers.TLS.State
	httpState := result.Layers.HTTP.State
	business := result.Layers.Business.State

	if connect != LayerUnknown && dns != LayerAvailable {
		return false
	}
	if tlsState != LayerUnknown && (dns != LayerAvailable || connect != LayerAvailable) {
		return false
	}
	if httpState != LayerUnknown && (dns != LayerAvailable || connect != LayerAvailable || tlsState != LayerAvailable) {
		return false
	}
	if business != LayerUnknown && httpState != LayerAvailable {
		return false
	}
	if httpState == LayerAvailable {
		return result.HTTPStatus != nil && result.ContentDigest != ""
	}
	return result.ContentDigest == ""
}

func validLayerResults(result ProbeResult, target Target) bool {
	layers := []LayerResult{result.Layers.DNS, result.Layers.Connect, result.Layers.TLS, result.Layers.HTTP, result.Layers.Business}
	maxLatency := int64(target.TimeoutSeconds+1) * 1000
	for index, layer := range layers {
		if !validLayerState(layer.State) || !validLayerReason(layer.Reason) || layer.LatencyMillis < 0 || layer.LatencyMillis > maxLatency {
			return false
		}
		if layer.ObservedAt.Before(result.AttemptedAt) || layer.ObservedAt.After(result.CompletedAt) || layer.ExpiresAt.Before(result.ExpiresAt.Add(-time.Duration(target.TimeoutSeconds+1)*time.Second)) || layer.ExpiresAt.After(result.ExpiresAt) {
			return false
		}
		if index != len(layers)-1 && layer.RetryAfterSeconds != 0 {
			return false
		}
	}
	retry := result.Layers.Business.RetryAfterSeconds
	if retry < 0 || retry > int64(maxRetryAfter/time.Second) {
		return false
	}
	if result.Conclusion == ConclusionRateLimited {
		return retry >= 0
	}
	return retry == 0
}

func validLayerState(state LayerState) bool {
	switch state {
	case LayerUnknown, LayerAvailable, LayerDegraded, LayerRestricted, LayerUnavailable, LayerRateLimited:
		return true
	}
	return false
}

func validProbeErrorClass(value string) bool {
	if value == "" {
		return true
	}
	return allowedProbeText[value]
}

func validLayerReason(value string) bool {
	return value != "" && allowedProbeText[value]
}

var allowedProbeText = map[string]bool{
	"access_restricted": true, "canceled": true, "catalog_digest_mismatch": true,
	"connect_failure": true, "contract_matched": true, "contract_mismatch": true,
	"dns_failure": true, "dns_timeout": true, "http_response_received": true,
	"http_transport_failure": true, "invalid_catalog": true, "invalid_probe_id": true,
	"invalid_probe_input": true, "invalid_resolved_target": true, "not_observed": true,
	"probe_canceled": true, "rate_limited": true, "redirect_blocked": true,
	"resolved_and_pinned": true, "response_read_failed": true, "response_too_large": true,
	"response_unusable": true, "restricted": true, "run_id_unavailable": true,
	"service_failure": true, "target_not_allowlisted": true, "tcp_connected": true,
	"timeout": true, "tls_failure": true, "tls_verified": true,
	"transport_unavailable": true, "unexpected_http_status": true,
}

func validSpoolStatePair(conclusion Conclusion, outcome Outcome) bool {
	switch outcome {
	case OutcomePass:
		return conclusion == ConclusionAvailable
	case OutcomeFail:
		return conclusion == ConclusionUnavailable
	case OutcomeIndeterminate:
		switch conclusion {
		case ConclusionUnknown, ConclusionRestricted, ConclusionRateLimited:
			return true
		}
	}
	return false
}

func spoolContentDigest(schema, catalogDigest string, result ProbeResult) (string, error) {
	payload, err := json.Marshal(spoolDigestPayload{Schema: schema, CatalogDigest: catalogDigest, Result: result})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func spoolSegmentFileName(segment spoolSegment) string {
	digest := strings.TrimPrefix(segment.Digest, "sha256:")
	if len(digest) > 16 {
		digest = digest[:16]
	}
	return fmt.Sprintf("%020d-%s.json", segment.Result.CompletedAt.UnixNano(), digest)
}

func validSpoolCatalogDigest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, char := range value[len("sha256:"):] {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
			return false
		}
	}
	return true
}

func normalizeSpoolLimits(entries int, bytes int64) (int, int64, error) {
	if entries == 0 {
		entries = DefaultSpoolMaxEntries
	}
	if bytes == 0 {
		bytes = DefaultSpoolMaxBytes
	}
	if entries < 1 || entries > DefaultSpoolMaxEntries {
		return 0, 0, fmt.Errorf("probe spool entry limit must be between 1 and %d", DefaultSpoolMaxEntries)
	}
	if bytes < MaximumSpoolSegmentBytes || bytes > DefaultSpoolMaxBytes {
		return 0, 0, fmt.Errorf("probe spool byte limit must be between %d and %d", MaximumSpoolSegmentBytes, DefaultSpoolMaxBytes)
	}
	return entries, bytes, nil
}

func secureSpoolDirectory(directory string, create bool) (string, error) {
	if strings.TrimSpace(directory) == "" {
		return "", errors.New("probe spool directory is required")
	}
	absDirectory, err := filepath.Abs(directory)
	if err != nil {
		return "", fmt.Errorf("resolve probe spool directory: %w", err)
	}
	info, err := os.Lstat(absDirectory)
	if errors.Is(err, os.ErrNotExist) && create {
		if err := os.MkdirAll(absDirectory, 0o700); err != nil {
			return "", fmt.Errorf("create probe spool directory: %w", err)
		}
		info, err = os.Lstat(absDirectory)
	}
	if err != nil {
		return "", fmt.Errorf("inspect probe spool directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", errors.New("probe spool path must be a real directory")
	}
	if create {
		if err := os.Chmod(absDirectory, 0o700); err != nil {
			return "", fmt.Errorf("restrict probe spool directory: %w", err)
		}
	}
	segments := filepath.Join(absDirectory, spoolSegmentsDirectory)
	segmentsInfo, segmentErr := os.Lstat(segments)
	if errors.Is(segmentErr, os.ErrNotExist) && create {
		if err := os.Mkdir(segments, 0o700); err != nil {
			return "", fmt.Errorf("create probe segment directory: %w", err)
		}
		segmentsInfo, segmentErr = os.Lstat(segments)
	}
	if segmentErr != nil || segmentsInfo.Mode()&os.ModeSymlink != 0 || !segmentsInfo.IsDir() {
		return "", errors.New("probe segment path must be a real directory")
	}
	if create {
		if err := os.Chmod(segments, 0o700); err != nil {
			return "", fmt.Errorf("restrict probe segment directory: %w", err)
		}
	}
	return absDirectory, nil
}
