// candidate-guard validates the M2b container envelope without issuing any
// DNS or network request. It is deliberately not the M2b probe agent.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"chengwang/internal/probe"
)

const healthSchema = "chengwang.m2b-candidate-guard-health/v1"

type healthRecord struct {
	Schema       string    `json:"schema"`
	State        string    `json:"state"`
	UpdatedAt    time.Time `json:"updatedAt"`
	Catalog      string    `json:"catalogDigest"`
	ActiveProbes bool      `json:"activeProbes"`
	AdvisoryOnly bool      `json:"advisoryOnly"`
}

func main() {
	if err := run(os.Args[1:], time.Now); err != nil {
		log.Printf("candidate guard stopped with error: %v", err)
		os.Exit(1)
	}
}

func run(args []string, now func() time.Time) error {
	if len(args) == 0 {
		return errors.New("command is required: serve or health")
	}
	switch args[0] {
	case "serve":
		return serve(args[1:], now)
	case "health":
		return health(args[1:], now)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func serve(args []string, now func() time.Time) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	catalogPath := flags.String("catalog", "", "read-only catalog path")
	spoolPath := flags.String("spool", "", "candidate-only spool directory")
	healthPath := flags.String("health-file", "", "tmpfs health record")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return errors.New("invalid serve arguments")
	}
	if *catalogPath == "" || *spoolPath == "" || *healthPath == "" {
		return errors.New("catalog, spool, and health-file are required")
	}

	catalog, err := readCatalog(*catalogPath)
	if err != nil {
		return err
	}
	if err := verifyWritableDirectory(*spoolPath); err != nil {
		return fmt.Errorf("verify candidate spool: %w", err)
	}
	if err := verifyHealthLocation(*healthPath, *spoolPath); err != nil {
		return err
	}

	signals := make(chan os.Signal, 2)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)

	write := func() error {
		return writeHealth(*healthPath, healthRecord{
			Schema:       healthSchema,
			State:        "quarantine_ready",
			UpdatedAt:    now().UTC(),
			Catalog:      catalog.Digest,
			ActiveProbes: false,
			AdvisoryOnly: true,
		})
	}
	if err := write(); err != nil {
		return err
	}
	log.Printf("M2b candidate guard ready (catalogDigest=%s, activeProbes=false)", catalog.Digest)

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case received := <-signals:
			log.Printf("received shutdown signal %s", received)
			if err := os.Remove(*healthPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("remove health record: %w", err)
			}
			log.Printf("M2b candidate guard shutdown complete")
			return nil
		case <-ticker.C:
			if err := write(); err != nil {
				return err
			}
		}
	}
}

func health(args []string, now func() time.Time) error {
	flags := flag.NewFlagSet("health", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	healthPath := flags.String("health-file", "", "tmpfs health record")
	maxAge := flags.Duration("max-age", 20*time.Second, "maximum heartbeat age")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *healthPath == "" || *maxAge <= 0 {
		return errors.New("invalid health arguments")
	}

	raw, err := os.ReadFile(*healthPath)
	if err != nil {
		return fmt.Errorf("read health record: %w", err)
	}
	var record healthRecord
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return fmt.Errorf("decode health record: %w", err)
	}
	if err := requireEOF(decoder); err != nil {
		return err
	}
	if record.Schema != healthSchema || record.State != "quarantine_ready" || record.ActiveProbes || !record.AdvisoryOnly {
		return errors.New("health record violates the quarantine contract")
	}
	if len(record.Catalog) != 64 {
		return errors.New("health record has an invalid catalog digest")
	}
	current := now().UTC()
	if record.UpdatedAt.After(current.Add(5 * time.Second)) {
		return errors.New("health record is from the future")
	}
	if current.Sub(record.UpdatedAt) > *maxAge {
		return errors.New("health record is stale")
	}
	return nil
}

func readCatalog(path string) (probe.Catalog, error) {
	if err := rejectSymlinkPathComponents(path); err != nil {
		return probe.Catalog{}, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return probe.Catalog{}, fmt.Errorf("inspect catalog: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return probe.Catalog{}, errors.New("catalog must be a regular non-symlink file")
	}
	file, err := os.Open(path)
	if err != nil {
		return probe.Catalog{}, fmt.Errorf("open catalog: %w", err)
	}
	defer file.Close()
	catalog, err := probe.ParseCatalog(file)
	if err != nil {
		return probe.Catalog{}, fmt.Errorf("parse catalog: %w", err)
	}
	return catalog, nil
}

func verifyWritableDirectory(path string) error {
	if err := rejectSymlinkPathComponents(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("spool must be a non-symlink directory")
	}
	file, err := os.CreateTemp(path, ".candidate-write-check-*")
	if err != nil {
		return err
	}
	name := file.Name()
	if _, err := file.Write([]byte("candidate-only\n")); err != nil {
		file.Close()
		_ = os.Remove(name)
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		_ = os.Remove(name)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	return os.Remove(name)
}

func verifyHealthLocation(healthPath, spoolPath string) error {
	healthDir := filepath.Clean(filepath.Dir(healthPath))
	spoolDir := filepath.Clean(spoolPath)
	if err := rejectSymlinkPathComponents(healthDir); err != nil {
		return err
	}
	if healthDir == spoolDir || strings.HasPrefix(healthDir+string(os.PathSeparator), spoolDir+string(os.PathSeparator)) {
		return errors.New("health record must not be written into the durable spool")
	}
	info, err := os.Lstat(healthDir)
	if err != nil {
		return fmt.Errorf("inspect health directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("health directory must be a non-symlink directory")
	}
	return nil
}

func writeHealth(path string, record healthRecord) error {
	raw, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode health record: %w", err)
	}
	raw = append(raw, '\n')
	temporaryFile, err := os.CreateTemp(filepath.Dir(path), ".candidate-health-*.tmp")
	if err != nil {
		return fmt.Errorf("write health record: %w", err)
	}
	temporary := temporaryFile.Name()
	closed := false
	defer func() {
		if !closed {
			_ = temporaryFile.Close()
		}
		_ = os.Remove(temporary)
	}()
	if err := temporaryFile.Chmod(0o600); err != nil {
		return fmt.Errorf("restrict health record: %w", err)
	}
	if _, err := temporaryFile.Write(raw); err != nil {
		return fmt.Errorf("write health record: %w", err)
	}
	if err := temporaryFile.Sync(); err != nil {
		return fmt.Errorf("sync health record: %w", err)
	}
	if err := temporaryFile.Close(); err != nil {
		return fmt.Errorf("close health record: %w", err)
	}
	closed = true
	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("replace health record: %w", err)
	}
	return nil
}

func rejectSymlinkPathComponents(path string) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve path: %w", err)
	}
	volume := filepath.VolumeName(absolute)
	remainder := strings.TrimPrefix(absolute, volume)
	current := volume + string(filepath.Separator)
	for _, component := range strings.FieldsFunc(remainder, func(r rune) bool { return r == '/' || r == '\\' }) {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("inspect path component %q: %w", current, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("path component %q must not be a symbolic link", current)
		}
	}
	return nil
}

func requireEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("health record contains more than one JSON value")
		}
		return fmt.Errorf("decode trailing health data: %w", err)
	}
	return nil
}
