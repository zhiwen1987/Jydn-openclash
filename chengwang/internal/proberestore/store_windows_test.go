//go:build windows

package proberestore

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func secureTempDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestWindowsOpenIsReadOnlyAndWritesUnsupported(t *testing.T) {
	d := secureTempDir(t)
	s, err := Open(d)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Create(validJournal(t)); !errors.Is(err, ErrDurabilityUnsupported) {
		t.Fatalf("Create=%v", err)
	}
}

func TestWindowsCanParseControlRecordReadOnly(t *testing.T) {
	d := secureTempDir(t)
	j := validJournal(t)
	r := newControl(j, nil)
	b, _ := json.Marshal(r)
	if err := os.WriteFile(filepath.Join(d, controlFilename), b, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(d)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, err := s.Load()
	if err != nil || got.OperationID != j.OperationID {
		t.Fatalf("Load=%v %v", got, err)
	}
	if err := s.Save(advance(t, j, PhaseLocked)); !errors.Is(err, ErrDurabilityUnsupported) {
		t.Fatalf("Save=%v", err)
	}
}
