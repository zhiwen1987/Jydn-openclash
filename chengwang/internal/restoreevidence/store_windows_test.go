//go:build windows

package restoreevidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"chengwang/internal/restorecontracts"
)

func TestWindowsPublishIsExplicitlyUnsupported(t *testing.T) {
	raw, context, clock := evidenceFixture(t)
	s, err := openForTest(t.TempDir(), testOptions{clock: func() (clockSnapshot, error) { return clock, nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	result, err := s.Publish(raw, context)
	if !errors.Is(err, ErrUnsupported) || result.CommitState() != NotCommitted || string(result.RawBytes()) != string(raw) {
		t.Fatalf("result state=%s err=%v", result.CommitState(), err)
	}
	if _, err := s.Read(context); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("reliable read error=%v", err)
	}
}

func TestWindowsDiagnosticReadValidatesRawContracts(t *testing.T) {
	raw, context, _ := evidenceFixture(t)
	cases := []struct {
		name    string
		mutate  func([]byte, restorecontracts.EvidenceContext) ([]byte, restorecontracts.EvidenceContext)
		wantErr bool
	}{
		{name: "valid", mutate: func(b []byte, c restorecontracts.EvidenceContext) ([]byte, restorecontracts.EvidenceContext) {
			return b, c
		}},
		{name: "missing field", wantErr: true, mutate: func(b []byte, c restorecontracts.EvidenceContext) ([]byte, restorecontracts.EvidenceContext) {
			var value map[string]any
			_ = json.Unmarshal(b, &value)
			delete(value, "schema")
			b, _ = json.Marshal(value)
			return withRawHash(b, c)
		}},
		{name: "digest mismatch", wantErr: true, mutate: func(b []byte, c restorecontracts.EvidenceContext) ([]byte, restorecontracts.EvidenceContext) {
			b = append(append([]byte(nil), b...), ' ')
			return b, c
		}},
		{name: "expired", wantErr: true, mutate: func(b []byte, c restorecontracts.EvidenceContext) ([]byte, restorecontracts.EvidenceContext) {
			var value map[string]any
			_ = json.Unmarshal(b, &value)
			value["expiresUnix"] = fixtureNow.Add(-time.Second).Unix()
			b, _ = json.Marshal(value)
			return withRawHash(b, c)
		}},
		{name: "future", wantErr: true, mutate: func(b []byte, c restorecontracts.EvidenceContext) ([]byte, restorecontracts.EvidenceContext) {
			var value map[string]any
			_ = json.Unmarshal(b, &value)
			value["capturedUnix"] = fixtureNow.Add(10 * time.Second).Unix()
			value["expiresUnix"] = fixtureNow.Add(20 * time.Second).Unix()
			b, _ = json.Marshal(value)
			return withRawHash(b, c)
		}},
		{name: "boot mismatch", wantErr: true, mutate: func(b []byte, c restorecontracts.EvidenceContext) ([]byte, restorecontracts.EvidenceContext) {
			c.BootID = "223e4567-e89b-42d3-a456-426614174000"
			return b, c
		}},
		{name: "boottime stale", wantErr: true, mutate: func(b []byte, c restorecontracts.EvidenceContext) ([]byte, restorecontracts.EvidenceContext) {
			c.CurrentBoottimeNS += uint64(10 * time.Second)
			return b, c
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			input, expected := tc.mutate(append([]byte(nil), raw...), context)
			name, err := evidenceNameFromContext(expected)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, name), input, 0o600); err != nil {
				t.Fatal(err)
			}
			s, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			result, err := s.ReadDiagnostic(expected)
			if tc.wantErr && err == nil {
				t.Fatal("expected rejection")
			}
			if !tc.wantErr {
				if err != nil || result.Reliability() != ReliabilityDiagnostic || string(result.RawBytes()) != string(raw) {
					t.Fatalf("result=%+v err=%v", result, err)
				}
			}
		})
	}
}

func TestWindowsDiagnosticRejectsHardlinkAndSymlink(t *testing.T) {
	raw, context, _ := evidenceFixture(t)
	name, _ := evidenceNameFromContext(context)
	t.Run("hardlink", func(t *testing.T) {
		dir := t.TempDir()
		source := filepath.Join(dir, "source.json")
		if err := os.WriteFile(source, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(source, filepath.Join(dir, name)); err != nil {
			t.Skipf("hardlink unavailable: %v", err)
		}
		s, err := Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		if _, err := s.ReadDiagnostic(context); !errors.Is(err, ErrUnsafeObject) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("symlink", func(t *testing.T) {
		dir := t.TempDir()
		source := filepath.Join(dir, "source.json")
		if err := os.WriteFile(source, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(source, filepath.Join(dir, name)); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		s, err := Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		if _, err := s.ReadDiagnostic(context); !errors.Is(err, ErrUnsafeObject) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestWindowsRejectsADSDevicesAndAmbiguousLeafNames(t *testing.T) {
	for _, name := range []string{
		"restore:stream.json",
		"restore?.json",
		"restore.json.",
		"restore.json ",
		"CON.00000000000000000002.INPUT_BOUND.json",
		"com1.00000000000000000002.INPUT_BOUND.json",
	} {
		if err := safeWindowsLeaf(name); !errors.Is(err, ErrUnsafeObject) {
			t.Fatalf("%q: %v", name, err)
		}
	}
	if err := safeWindowsLeaf("restore-01.00000000000000000002.INPUT_BOUND.json"); err != nil {
		t.Fatalf("safe leaf rejected: %v", err)
	}
}

func withRawHash(raw []byte, context restorecontracts.EvidenceContext) ([]byte, restorecontracts.EvidenceContext) {
	sum := sha256.Sum256(raw)
	context.RawBytesSHA256 = hex.EncodeToString(sum[:])
	return raw, context
}
