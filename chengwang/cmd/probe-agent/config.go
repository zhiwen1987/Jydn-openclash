package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"chengwang/internal/probe"
)

const maxCAFileBytes = 1 << 20

type config struct {
	catalogPath      string
	spoolDirectory   string
	ledgerDirectory  string
	doTUpstream      netip.AddrPort
	doTServerName    string
	doTCAPath        string
	healthFilePath   string
	resolverTimeout  time.Duration
	runnerTimeout    time.Duration
	concurrency      int
	queueSize        int
	startsPerMinute  int
	spoolMaxEntries  int
	spoolMaxBytes    int64
	ledgerMaxEntries int
	ledgerMaxBytes   int64
}

func parseConfig(args []string, output io.Writer) (config, error) {
	if output == nil {
		output = io.Discard
	}
	if err := rejectAmbiguousArguments(args); err != nil {
		return config{}, err
	}
	flags := flag.NewFlagSet("probe-agent", flag.ContinueOnError)
	flags.SetOutput(output)
	var upstream string
	result := config{}
	flags.StringVar(&result.catalogPath, "catalog", "", "path to the immutable probe catalog")
	flags.StringVar(&result.spoolDirectory, "spool-dir", "", "independent result spool directory")
	flags.StringVar(&result.ledgerDirectory, "ledger-dir", "", "independent durable start-ledger directory")
	flags.StringVar(&upstream, "dot-upstream", "", "fixed DNS-over-TLS endpoint as IP:port")
	flags.StringVar(&result.doTServerName, "dot-server-name", "", "TLS SNI name for the fixed DoT endpoint")
	flags.StringVar(&result.doTCAPath, "dot-ca", "", "optional PEM CA bundle for the DoT endpoint")
	flags.StringVar(&result.healthFilePath, "health-file", "", "optional independent tmpfs health record path")
	flags.DurationVar(&result.resolverTimeout, "resolver-timeout", 5*time.Second, "total timeout for one fixed-DoT resolution")
	flags.DurationVar(&result.runnerTimeout, "runner-timeout", 10*time.Second, "maximum total HTTPS probe timeout")
	flags.IntVar(&result.concurrency, "concurrency", probe.DefaultProbeConcurrency, "global probe concurrency")
	flags.IntVar(&result.queueSize, "queue-size", probe.DefaultProbeQueueSize, "bounded scheduler queue size")
	flags.IntVar(&result.startsPerMinute, "starts-per-minute", probe.DefaultProbeStartsMinute, "global durable start budget per minute")
	flags.IntVar(&result.spoolMaxEntries, "spool-max-entries", probe.DefaultSpoolMaxEntries, "maximum immutable result segments")
	flags.Int64Var(&result.spoolMaxBytes, "spool-max-bytes", probe.DefaultSpoolMaxBytes, "maximum result spool bytes")
	flags.IntVar(&result.ledgerMaxEntries, "ledger-max-entries", probe.DefaultStartLedgerEntries, "maximum durable start facts")
	flags.Int64Var(&result.ledgerMaxBytes, "ledger-max-bytes", probe.DefaultStartLedgerBytes, "maximum durable start-ledger bytes")
	if err := flags.Parse(args); err != nil {
		return config{}, err
	}
	if flags.NArg() != 0 {
		return config{}, errors.New("positional arguments are prohibited")
	}
	for name, value := range map[string]string{
		"catalog": result.catalogPath, "spool-dir": result.spoolDirectory,
		"ledger-dir": result.ledgerDirectory, "dot-upstream": upstream,
		"dot-server-name": result.doTServerName,
	} {
		if strings.TrimSpace(value) == "" {
			return config{}, fmt.Errorf("--%s is required", name)
		}
		if value != strings.TrimSpace(value) {
			return config{}, fmt.Errorf("--%s must not contain surrounding whitespace", name)
		}
	}
	parsedUpstream, err := netip.ParseAddrPort(upstream)
	if err != nil || !parsedUpstream.Addr().IsValid() || parsedUpstream.Port() == 0 {
		return config{}, errors.New("--dot-upstream must be a fixed IP:port with a non-zero port")
	}
	result.doTUpstream = parsedUpstream
	if err := validateIndependentPaths(result); err != nil {
		return config{}, err
	}
	// Constructors are the authoritative bound checks. They perform no network
	// I/O, so validating here cannot accidentally start a probe.
	if _, err := probe.NewFixedDoTResolver(probe.FixedDoTResolverConfig{
		Upstream: parsedUpstream, ServerName: result.doTServerName, Timeout: result.resolverTimeout,
	}); err != nil {
		return config{}, fmt.Errorf("invalid fixed DoT configuration: %w", err)
	}
	if _, err := probe.NewRunner(result.runnerTimeout); err != nil {
		return config{}, fmt.Errorf("invalid runner configuration: %w", err)
	}
	if result.concurrency < 1 || result.concurrency > 16 {
		return config{}, errors.New("--concurrency must be between 1 and 16")
	}
	if result.queueSize < result.concurrency || result.queueSize > probe.DefaultProbeQueueSize {
		return config{}, fmt.Errorf("--queue-size must be between concurrency and %d", probe.DefaultProbeQueueSize)
	}
	if result.startsPerMinute < 1 || result.startsPerMinute > probe.DefaultProbeStartsMinute {
		return config{}, fmt.Errorf("--starts-per-minute must be between 1 and %d", probe.DefaultProbeStartsMinute)
	}
	if result.spoolMaxEntries < 1 || result.spoolMaxEntries > probe.DefaultSpoolMaxEntries {
		return config{}, fmt.Errorf("--spool-max-entries must be between 1 and %d", probe.DefaultSpoolMaxEntries)
	}
	if result.spoolMaxBytes < probe.MaximumSpoolSegmentBytes || result.spoolMaxBytes > probe.DefaultSpoolMaxBytes {
		return config{}, fmt.Errorf("--spool-max-bytes must be between %d and %d", probe.MaximumSpoolSegmentBytes, probe.DefaultSpoolMaxBytes)
	}
	if result.ledgerMaxEntries < 1 || result.ledgerMaxEntries > probe.MaximumStartLedgerEntries {
		return config{}, fmt.Errorf("--ledger-max-entries must be between 1 and %d", probe.MaximumStartLedgerEntries)
	}
	if result.ledgerMaxBytes < probe.MinimumStartLedgerBytes || result.ledgerMaxBytes > probe.MaximumStartLedgerBytes {
		return config{}, fmt.Errorf("--ledger-max-bytes must be between %d and %d", probe.MinimumStartLedgerBytes, probe.MaximumStartLedgerBytes)
	}
	return result, nil
}

func rejectAmbiguousArguments(args []string) error {
	seen := make(map[string]struct{}, len(args))
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if argument == "-h" || argument == "--help" {
			continue
		}
		if argument == "--" || !strings.HasPrefix(argument, "--") || len(argument) == 2 {
			return fmt.Errorf("only named --flag arguments are accepted: %q", argument)
		}
		nameValue := argument[2:]
		name, _, hasInlineValue := strings.Cut(nameValue, "=")
		if name == "" {
			return errors.New("empty flag name is prohibited")
		}
		if _, duplicate := seen[name]; duplicate {
			return fmt.Errorf("duplicate flag --%s is prohibited", name)
		}
		seen[name] = struct{}{}
		if !hasInlineValue && index+1 < len(args) && !strings.HasPrefix(args[index+1], "-") {
			index++
		}
	}
	return nil
}

func validateIndependentPaths(value config) error {
	paths := map[string]string{
		"catalog":    value.catalogPath,
		"spool-dir":  value.spoolDirectory,
		"ledger-dir": value.ledgerDirectory,
	}
	if value.doTCAPath != "" {
		if value.doTCAPath != strings.TrimSpace(value.doTCAPath) {
			return errors.New("--dot-ca must not contain surrounding whitespace")
		}
		paths["dot-ca"] = value.doTCAPath
	}
	if value.healthFilePath != "" {
		if value.healthFilePath != strings.TrimSpace(value.healthFilePath) {
			return errors.New("--health-file must not contain surrounding whitespace")
		}
		paths["health-file"] = value.healthFilePath
	}
	abs := make(map[string]string, len(paths))
	for name, path := range paths {
		resolved, err := filepath.Abs(path)
		if err != nil {
			return fmt.Errorf("resolve --%s: %w", name, err)
		}
		abs[name] = filepath.Clean(resolved)
	}
	if pathsOverlap(abs["spool-dir"], abs["ledger-dir"]) {
		return errors.New("--spool-dir and --ledger-dir must be independent, non-overlapping directories")
	}
	for _, fileName := range []string{"catalog", "dot-ca"} {
		filePath, exists := abs[fileName]
		if !exists {
			continue
		}
		if pathsOverlap(filePath, abs["spool-dir"]) || pathsOverlap(filePath, abs["ledger-dir"]) {
			return fmt.Errorf("--%s must be outside writable spool and ledger directories", fileName)
		}
	}
	if healthPath, exists := abs["health-file"]; exists {
		if pathsOverlap(healthPath, abs["spool-dir"]) || pathsOverlap(healthPath, abs["ledger-dir"]) {
			return errors.New("--health-file must be outside writable spool and ledger directories")
		}
		for _, immutableName := range []string{"catalog", "dot-ca"} {
			if immutablePath, ok := abs[immutableName]; ok && healthPath == immutablePath {
				return fmt.Errorf("--health-file must not replace --%s", immutableName)
			}
		}
	}
	return nil
}

func pathsOverlap(first, second string) bool {
	return pathContains(first, second) || pathContains(second, first)
}

func pathContains(parent, candidate string) bool {
	relative, err := filepath.Rel(parent, candidate)
	if err != nil {
		return false
	}
	return relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}

func loadCatalog(path string) (probe.Catalog, error) {
	raw, err := readRegularFile(path, probe.MaxCatalogBytes)
	if err != nil {
		return probe.Catalog{}, fmt.Errorf("read catalog file: %w", err)
	}
	catalog, err := probe.ParseCatalogBytes(raw)
	if err != nil {
		return probe.Catalog{}, fmt.Errorf("parse catalog file: %w", err)
	}
	return catalog, nil
}

func loadCAPool(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := readRegularFile(path, maxCAFileBytes)
	if err != nil {
		return nil, fmt.Errorf("read DoT CA file: %w", err)
	}
	pool := x509.NewCertPool()
	certificates := 0
	remaining := raw
	for len(bytes.TrimSpace(remaining)) != 0 {
		block, rest := pem.Decode(remaining)
		if block == nil {
			return nil, errors.New("DoT CA file contains non-PEM data")
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errors.New("DoT CA file may contain only headerless CERTIFICATE blocks")
		}
		parsed, err := x509.ParseCertificates(block.Bytes)
		if err != nil || len(parsed) != 1 {
			return nil, errors.New("DoT CA file contains an invalid certificate block")
		}
		pool.AddCert(parsed[0])
		certificates++
		remaining = rest
	}
	if certificates == 0 {
		return nil, errors.New("DoT CA file contains no certificates")
	}
	return pool, nil
}

func readRegularFile(path string, maximum int64) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("file path is required")
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve file path: %w", err)
	}
	if err := rejectExistingSymlinkComponents(absPath); err != nil {
		return nil, err
	}
	before, err := os.Lstat(absPath)
	if err != nil {
		return nil, fmt.Errorf("inspect file: %w", err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, errors.New("path must identify a non-symlink regular file")
	}
	if before.Size() < 0 || before.Size() > maximum {
		return nil, fmt.Errorf("file exceeds %d bytes", maximum)
	}
	file, err := os.Open(absPath)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect open file: %w", err)
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, errors.New("file identity changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	if int64(len(raw)) > maximum {
		return nil, fmt.Errorf("file exceeds %d bytes", maximum)
	}
	return raw, nil
}

func rejectExistingSymlinkComponents(path string) error {
	volume := filepath.VolumeName(path)
	remainder := strings.TrimPrefix(path, volume)
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
