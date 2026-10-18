package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"chengwang/internal/probe"
)

func TestValidateStateCommandDispatchAndStrictArguments(t *testing.T) {
	base := t.TempDir()
	catalog := commandTestCatalog(t)
	catalogRaw, err := json.Marshal(catalog)
	if err != nil {
		t.Fatal(err)
	}
	catalogPath := filepath.Join(base, "catalog.json")
	if err := os.WriteFile(catalogPath, catalogRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	spoolDirectory := filepath.Join(base, "probe-spool")
	ledgerDirectory := filepath.Join(base, "probe-state", "probe-ledger")
	store, err := probe.OpenStore(spoolDirectory, catalog, probe.StoreLimits{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Add(-time.Second).Truncate(time.Millisecond)
	current := now
	ledger, err := probe.OpenStartLedger(ledgerDirectory, catalog, probe.StartLedgerOptions{Now: func() time.Time { return current }})
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.RecordStart("command-start", catalog.Probes[0].ID, current); err != nil {
		t.Fatal(err)
	}
	result := commandTestResult(catalog, current, "command-result", "command-start")
	if err := store.Append(result); err != nil {
		t.Fatal(err)
	}
	current = result.CompletedAt
	if err := ledger.Settle("command-start", result); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}

	arguments := []string{
		"validate-state", "--catalog", catalogPath, "--spool-dir", spoolDirectory,
		"--ledger-dir", ledgerDirectory, "--expected-ledger-writer-dir", ledgerDirectory,
	}
	var output bytes.Buffer
	var diagnostics bytes.Buffer
	commandErr := execute(context.Background(), arguments, &output, &diagnostics)
	uid, gid := testStateOwnerIDs(t, spoolDirectory)
	if runtime.GOOS == "windows" {
		if commandErr == nil || !strings.Contains(commandErr.Error(), "ownership metadata is unavailable") {
			t.Fatalf("Windows fail-closed ownership error = %v", commandErr)
		}
	} else if uid != candidateProbeStateOwnerID || gid != candidateProbeStateOwnerID {
		if commandErr == nil || !strings.Contains(commandErr.Error(), "want uid=10001 gid=10001") {
			t.Fatalf("non-candidate owner error = %v", commandErr)
		}
	} else {
		if commandErr != nil {
			t.Fatalf("execute(validate-state) error = %v", commandErr)
		}
		if diagnostics.Len() != 0 {
			t.Fatalf("validate-state wrote success output to stderr: %q", diagnostics.String())
		}
		var report probe.StateValidationReport
		if err := json.Unmarshal(output.Bytes(), &report); err != nil {
			t.Fatalf("decode validation report: %v; output=%q", err, output.String())
		}
		if report.Schema != probe.StateValidationSchemaV1 || report.SpoolResults != 1 || report.LatestSettled != 1 || !report.ReadOnlyValidation {
			t.Fatalf("unexpected command report: %+v", report)
		}
	}

	missingWriter := []string{
		"validate-state", "--catalog", catalogPath, "--spool-dir", spoolDirectory,
		"--ledger-dir", ledgerDirectory,
	}
	if err := execute(context.Background(), missingWriter, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "expected-ledger-writer-dir is required") {
		t.Fatalf("missing writer path error = %v", err)
	}
	duplicate := append(append([]string(nil), arguments...), "--catalog", catalogPath)
	if err := execute(context.Background(), duplicate, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "duplicate flag") {
		t.Fatalf("duplicate flag error = %v", err)
	}
	wrongWriter := append([]string(nil), arguments...)
	wrongWriter[8] = "relative/writer"
	if err := execute(context.Background(), wrongWriter, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "clean absolute runtime writer path") {
		t.Fatalf("wrong writer path error = %v", err)
	}
}

func testStateOwnerIDs(t *testing.T, path string) (uint64, uint64) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	value := reflect.ValueOf(info.Sys())
	if value.IsValid() && value.Kind() == reflect.Pointer && !value.IsNil() {
		value = value.Elem()
		uid, gid := value.FieldByName("Uid"), value.FieldByName("Gid")
		if uid.IsValid() && gid.IsValid() && uid.CanUint() && gid.CanUint() {
			return uid.Uint(), gid.Uint()
		}
	}
	return 10001, 10001
}
