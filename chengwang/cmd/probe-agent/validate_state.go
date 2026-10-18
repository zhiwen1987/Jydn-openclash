package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"chengwang/internal/probe"
)

const candidateProbeStateOwnerID = uint64(10001)

type validateStateConfig struct {
	catalogPath                   string
	spoolDirectory                string
	ledgerDirectory               string
	expectedLedgerWriterDirectory string
	spoolMaxEntries               int
	spoolMaxBytes                 int64
	ledgerMaxEntries              int
	ledgerMaxBytes                int64
}

// runValidateStateCommand performs an offline, read-only validation and emits
// one bounded JSON report on success. It opens and holds the two existing
// writer locks read-only, but does not create or write locks, repair state,
// remove temporary files, or perform network I/O.
func runValidateStateCommand(args []string, output, diagnostics io.Writer, now func() time.Time) error {
	if output == nil {
		output = io.Discard
	}
	if diagnostics == nil {
		diagnostics = io.Discard
	}
	if now == nil {
		return errors.New("state validation current-time source is required")
	}
	if err := rejectAmbiguousArguments(args); err != nil {
		return err
	}
	flags := flag.NewFlagSet("probe-agent validate-state", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	value := validateStateConfig{}
	flags.StringVar(&value.catalogPath, "catalog", "", "immutable probe catalog path")
	flags.StringVar(&value.spoolDirectory, "spool-dir", "", "offline probe result spool directory")
	flags.StringVar(&value.ledgerDirectory, "ledger-dir", "", "offline durable start-ledger directory")
	flags.StringVar(&value.expectedLedgerWriterDirectory, "expected-ledger-writer-dir", "", "absolute runtime writer path embedded in ledger snapshots")
	flags.IntVar(&value.spoolMaxEntries, "spool-max-entries", probe.DefaultSpoolMaxEntries, "maximum immutable result segments")
	flags.Int64Var(&value.spoolMaxBytes, "spool-max-bytes", probe.DefaultSpoolMaxBytes, "maximum result spool bytes")
	flags.IntVar(&value.ledgerMaxEntries, "ledger-max-entries", probe.DefaultStartLedgerEntries, "maximum durable start facts")
	flags.Int64Var(&value.ledgerMaxBytes, "ledger-max-bytes", probe.DefaultStartLedgerBytes, "maximum durable start-ledger bytes")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("validate-state positional arguments are prohibited")
	}
	for name, input := range map[string]string{
		"catalog": value.catalogPath, "spool-dir": value.spoolDirectory, "ledger-dir": value.ledgerDirectory,
		"expected-ledger-writer-dir": value.expectedLedgerWriterDirectory,
	} {
		if strings.TrimSpace(input) == "" {
			return fmt.Errorf("validate-state --%s is required", name)
		}
		if input != strings.TrimSpace(input) {
			return fmt.Errorf("validate-state --%s must not contain surrounding whitespace", name)
		}
	}
	cleanWriter := filepath.Clean(value.expectedLedgerWriterDirectory)
	if !filepath.IsAbs(cleanWriter) || cleanWriter != value.expectedLedgerWriterDirectory {
		return errors.New("validate-state --expected-ledger-writer-dir must be a clean absolute runtime writer path")
	}
	catalog, err := loadCatalog(value.catalogPath)
	if err != nil {
		return fmt.Errorf("validate-state catalog validation failed: %w", err)
	}
	report, err := probe.ValidateStateSnapshot(value.spoolDirectory, value.ledgerDirectory, probe.StateValidationOptions{
		Catalog: catalog, ExpectedLedgerWriterDirectory: value.expectedLedgerWriterDirectory, Now: now().UTC(),
		SpoolMaxEntries: value.spoolMaxEntries, SpoolMaxBytes: value.spoolMaxBytes,
		LedgerMaxEntries: value.ledgerMaxEntries, LedgerMaxBytes: value.ledgerMaxBytes,
		ExpectedOwnerUID: candidateProbeStateOwnerID, ExpectedOwnerGID: candidateProbeStateOwnerID, EnforceExpectedOwner: true,
	})
	if err != nil {
		return fmt.Errorf("validate-state failed: %w", err)
	}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(true)
	if err := encoder.Encode(report); err != nil {
		return fmt.Errorf("encode validate-state report: %w", err)
	}
	return nil
}
