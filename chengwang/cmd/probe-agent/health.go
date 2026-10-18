package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"chengwang/internal/probe"
)

const (
	probeAgentHealthSchema = "chengwang.probe-agent-health/v1"
	probeAgentHealthState  = "running"
	maximumHealthFileBytes = int64(8 << 10)
	defaultHealthInterval  = 5 * time.Second
	defaultHealthMaxAge    = 20 * time.Second
	maximumHealthMaxAge    = 5 * time.Minute
	healthFutureSkew       = 5 * time.Second
)

var catalogDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// probeAgentHealth contains process-local liveness and scheduler/storage
// safety facts only. It deliberately has no DNS, Internet, canary, node, path,
// target, or business-availability field.
type probeAgentHealth struct {
	Schema         string    `json:"schema"`
	State          string    `json:"state"`
	UpdatedAt      time.Time `json:"updatedAt"`
	CatalogDigest  string    `json:"catalogDigest"`
	Running        bool      `json:"running"`
	ClockHealthy   bool      `json:"clockHealthy"`
	StorageHealthy bool      `json:"storageHealthy"`
	Queued         int       `json:"queued"`
	Active         int       `json:"active"`
	Started        uint64    `json:"started"`
	Completed      uint64    `json:"completed"`
	Canceled       uint64    `json:"canceled"`
	BudgetSkipped  uint64    `json:"budgetSkipped"`
	QueueSkipped   uint64    `json:"queueSkipped"`
	SinkFailures   uint64    `json:"sinkFailures"`
	AdvisoryOnly   bool      `json:"advisoryOnly"`
	ActiveProbes   bool      `json:"activeProbes"`
}

type healthPublisher struct {
	path          string
	catalogDigest string
	status        func() probe.SchedulerStatus
	now           func() time.Time
	interval      time.Duration
	write         func(string, probeAgentHealth) error
}

func newHealthPublisher(path, catalogDigest string, status func() probe.SchedulerStatus) (*healthPublisher, error) {
	if path == "" {
		return nil, nil
	}
	if status == nil {
		return nil, errors.New("health scheduler status source is required")
	}
	absPath, err := validateHealthFileLocation(path)
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(absPath); err == nil {
		if err := validateExistingHealthFile(absPath); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect existing probe-agent health file: %w", err)
	}
	if !catalogDigestPattern.MatchString(catalogDigest) {
		return nil, errors.New("health catalog digest is invalid")
	}
	return &healthPublisher{
		path: absPath, catalogDigest: catalogDigest, status: status,
		now: time.Now, interval: defaultHealthInterval, write: writeHealthFile,
	}, nil
}

func (publisher *healthPublisher) run(ctx context.Context) error {
	if publisher == nil {
		return nil
	}
	if ctx == nil {
		return errors.New("health publisher context is nil")
	}
	if publisher.interval <= 0 || publisher.now == nil || publisher.write == nil || publisher.status == nil {
		return errors.New("health publisher is incomplete")
	}
	startupPoll := 10 * time.Millisecond
	for {
		status := publisher.status()
		if status.Running {
			if err := publisher.write(publisher.path, healthFromStatus(publisher.catalogDigest, publisher.now().UTC(), status)); err != nil {
				return fmt.Errorf("publish probe-agent health: %w", err)
			}
			break
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(startupPoll):
		}
	}

	ticker := time.NewTicker(publisher.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			status := publisher.status()
			if err := publisher.write(publisher.path, healthFromStatus(publisher.catalogDigest, publisher.now().UTC(), status)); err != nil {
				return fmt.Errorf("publish probe-agent health: %w", err)
			}
		}
	}
}

func healthFromStatus(catalogDigest string, now time.Time, status probe.SchedulerStatus) probeAgentHealth {
	return probeAgentHealth{
		Schema: probeAgentHealthSchema, State: probeAgentHealthState,
		UpdatedAt: now, CatalogDigest: catalogDigest,
		Running: status.Running, ClockHealthy: status.ClockHealthy,
		StorageHealthy: status.StorageHealthy, Queued: status.Queued,
		Active: status.Active, Started: status.Started, Completed: status.Completed,
		Canceled: status.Canceled, BudgetSkipped: status.BudgetSkipped,
		QueueSkipped: status.QueueSkipped, SinkFailures: status.SinkFailures,
		AdvisoryOnly: true, ActiveProbes: true,
	}
}

func runHealthCommand(args []string, output io.Writer, now func() time.Time) error {
	if output == nil {
		output = io.Discard
	}
	if now == nil {
		return errors.New("health current-time source is required")
	}
	if err := rejectAmbiguousArguments(args); err != nil {
		return err
	}
	flags := flag.NewFlagSet("probe-agent health", flag.ContinueOnError)
	flags.SetOutput(output)
	healthPath := flags.String("health-file", "", "probe-agent health record path")
	catalogPath := flags.String("catalog", "", "immutable catalog path used by the running agent")
	maxAge := flags.Duration("max-age", defaultHealthMaxAge, "maximum accepted heartbeat age")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("health positional arguments are prohibited")
	}
	if strings.TrimSpace(*healthPath) == "" || *healthPath != strings.TrimSpace(*healthPath) {
		return errors.New("health --health-file is required without surrounding whitespace")
	}
	if strings.TrimSpace(*catalogPath) == "" || *catalogPath != strings.TrimSpace(*catalogPath) {
		return errors.New("health --catalog is required without surrounding whitespace")
	}
	if *maxAge < time.Second || *maxAge > maximumHealthMaxAge {
		return fmt.Errorf("health --max-age must be between 1s and %s", maximumHealthMaxAge)
	}
	catalog, err := loadCatalog(*catalogPath)
	if err != nil {
		return err
	}
	record, err := readHealthFile(*healthPath)
	if err != nil {
		return err
	}
	return validateHealthRecord(record, catalog.Digest, now().UTC(), *maxAge, true)
}

func validateHealthRecord(record probeAgentHealth, expectedDigest string, now time.Time, maxAge time.Duration, requireHealthy bool) error {
	if record.Schema != probeAgentHealthSchema || record.State != probeAgentHealthState {
		return errors.New("probe-agent health schema or state is invalid")
	}
	if !catalogDigestPattern.MatchString(record.CatalogDigest) || record.CatalogDigest != expectedDigest {
		return errors.New("probe-agent health catalog digest does not match")
	}
	if !record.AdvisoryOnly || !record.ActiveProbes {
		return errors.New("probe-agent health mode flags are invalid")
	}
	if record.Queued < 0 || record.Queued > probe.DefaultProbeQueueSize || record.Active < 0 || record.Active > 16 {
		return errors.New("probe-agent health bounded counters are invalid")
	}
	if record.UpdatedAt.IsZero() || record.UpdatedAt.UnixNano() < 0 {
		return errors.New("probe-agent health timestamp is invalid")
	}
	if record.UpdatedAt.After(now.Add(healthFutureSkew)) {
		return errors.New("probe-agent health timestamp is in the future")
	}
	if now.Sub(record.UpdatedAt) > maxAge {
		return errors.New("probe-agent health heartbeat is stale")
	}
	if requireHealthy && (!record.Running || !record.ClockHealthy || !record.StorageHealthy) {
		return errors.New("probe-agent scheduler or storage is unhealthy")
	}
	return nil
}

func readHealthFile(path string) (probeAgentHealth, error) {
	absPath, err := validateHealthFileLocation(path)
	if err != nil {
		return probeAgentHealth{}, err
	}
	if err := validateExistingHealthFile(absPath); err != nil {
		return probeAgentHealth{}, err
	}
	raw, err := readRegularFile(absPath, maximumHealthFileBytes)
	if err != nil {
		return probeAgentHealth{}, fmt.Errorf("read probe-agent health: %w", err)
	}
	if err := rejectDuplicateHealthJSONKeys(raw); err != nil {
		return probeAgentHealth{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var record probeAgentHealth
	if err := decoder.Decode(&record); err != nil {
		return probeAgentHealth{}, fmt.Errorf("decode probe-agent health: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return probeAgentHealth{}, errors.New("probe-agent health must contain exactly one JSON value")
	}
	return record, nil
}

func writeHealthFile(path string, record probeAgentHealth) error {
	absPath, err := validateHealthFileLocation(path)
	if err != nil {
		return err
	}
	if err := validateHealthRecord(record, record.CatalogDigest, record.UpdatedAt, maximumHealthMaxAge, false); err != nil {
		return err
	}
	if _, err := os.Lstat(absPath); err == nil {
		if err := validateExistingHealthFile(absPath); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect probe-agent health destination: %w", err)
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode probe-agent health: %w", err)
	}
	raw = append(raw, '\n')
	if int64(len(raw)) > maximumHealthFileBytes {
		return errors.New("probe-agent health record exceeds its size limit")
	}
	directory := filepath.Dir(absPath)
	temporary, err := os.CreateTemp(directory, ".probe-agent-health-*.tmp")
	if err != nil {
		return fmt.Errorf("create probe-agent health temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("restrict probe-agent health temporary file: %w", err)
	}
	if _, err := temporary.Write(raw); err != nil {
		return fmt.Errorf("write probe-agent health temporary file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync probe-agent health temporary file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close probe-agent health temporary file: %w", err)
	}
	if err := replaceHealthFile(temporaryPath, absPath); err != nil {
		return fmt.Errorf("replace probe-agent health file: %w", err)
	}
	committed = true
	return syncHealthDirectory(directory)
}

func removeHealthFile(path string) error {
	if path == "" {
		return nil
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	info, err := os.Lstat(absPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("probe-agent health cleanup target is not a regular file")
	}
	if err := os.Remove(absPath); err != nil {
		return err
	}
	return syncHealthDirectory(filepath.Dir(absPath))
}

func validateHealthFileLocation(path string) (string, error) {
	if strings.TrimSpace(path) == "" || path != strings.TrimSpace(path) {
		return "", errors.New("probe-agent health file path is required without surrounding whitespace")
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve probe-agent health path: %w", err)
	}
	if err := rejectExistingSymlinkComponents(absPath); err != nil {
		return "", err
	}
	directory := filepath.Dir(absPath)
	info, err := os.Lstat(directory)
	if err != nil {
		return "", fmt.Errorf("inspect probe-agent health directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", errors.New("probe-agent health directory must be a non-symlink directory")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("probe-agent health directory must not grant group or other permissions")
	}
	if err := validateHealthDirectoryMetadata(info); err != nil {
		return "", err
	}
	return filepath.Clean(absPath), nil
}

func validateExistingHealthFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect probe-agent health file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("probe-agent health path must be a non-symlink regular file")
	}
	if info.Size() <= 0 || info.Size() > maximumHealthFileBytes {
		return errors.New("probe-agent health file size is invalid")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return errors.New("probe-agent health file must not grant group or other permissions")
	}
	if err := validateHealthFileMetadata(info); err != nil {
		return err
	}
	return nil
}

func rejectDuplicateHealthJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := consumeHealthJSONValue(decoder); err != nil {
		return fmt.Errorf("inspect probe-agent health JSON: %w", err)
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("probe-agent health JSON has trailing token %v", token)
		}
		return fmt.Errorf("inspect trailing probe-agent health JSON: %w", err)
	}
	return nil
}

func consumeHealthJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate object key %q", key)
			}
			seen[key] = struct{}{}
			if err := consumeHealthJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("object is not closed")
		}
	case '[':
		for decoder.More() {
			if err := consumeHealthJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("array is not closed")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}
