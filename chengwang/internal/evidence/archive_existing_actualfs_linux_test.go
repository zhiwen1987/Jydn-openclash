//go:build linux && a1actualfs

package evidence

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"chengwang/internal/nativefs"
)

func TestExistingArchiveSnapshotReadsWithoutMutation(t *testing.T) {
	dir := archiveActualFixture(t)
	limits := archiveFixtureLimits(t, dir)
	before := archiveFixtureBytes(t, dir)
	snapshot, err := OpenExistingArchiveSnapshot(dir, limits)
	if err != nil {
		t.Fatal(err)
	}
	anchor := snapshot.Anchor()
	if anchor.EventCount != 1 || anchor.EventCount != anchor.CheckpointCount || anchor.EventHead != anchor.CheckpointHead {
		t.Fatalf("unexpected evidence anchor counts or heads: %#v", anchor)
	}
	if anchor.Root.EntryCount != 3 || anchor.Lock.Length != 0 || anchor.Log.Length == 0 || anchor.Checkpoint.Length == 0 {
		t.Fatalf("unexpected file anchors: %#v", anchor)
	}
	if got := snapshot.Anchor(); got != anchor {
		t.Fatal("cached Anchor changed")
	}
	if err := snapshot.Revalidate(); err != nil {
		t.Fatal(err)
	}
	if got := snapshot.Anchor(); got != anchor {
		t.Fatal("Revalidate changed cached Anchor")
	}
	if err := snapshot.Close(); err != nil {
		t.Fatal(err)
	}
	if err := snapshot.Close(); err != nil {
		t.Fatalf("Close must be idempotent: %v", err)
	}
	if got := snapshot.Anchor(); got != anchor {
		t.Fatal("Close changed cached Anchor")
	}
	after := archiveFixtureBytes(t, dir)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("existing-only snapshot mutated source bytes or entries")
	}
}

func TestExistingArchiveSnapshotActualStateFormattingIsOpaque(t *testing.T) {
	dir := archiveActualFixture(t)
	snapshot, err := OpenExistingArchiveSnapshot(dir, archiveFixtureLimits(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	fdSentinel := strconv.FormatUint(uint64(snapshot.state.log.Fd()), 10)
	forms := []string{
		fmt.Sprintf("%v", snapshot),
		fmt.Sprintf("%+v", snapshot),
		fmt.Sprintf("%#v", snapshot),
		fmt.Sprintf("%v", *snapshot),
		fmt.Sprintf("%+v", *snapshot),
		fmt.Sprintf("%#v", *snapshot),
	}
	for _, rendered := range forms {
		if rendered != "evidence.ExistingArchiveSnapshot<redacted>" {
			t.Fatalf("snapshot formatting was not fixed redaction: %q", rendered)
		}
		for _, sentinel := range []string{dir, logFilename, checkpointFilename, lockFilename, "fd=", fdSentinel} {
			if strings.Contains(rendered, sentinel) {
				t.Fatalf("snapshot formatting leaked private sentinel %q: %q", sentinel, rendered)
			}
		}
	}
}

func TestExistingArchiveSnapshotLockContentionIsFixed(t *testing.T) {
	dir := archiveActualFixture(t)
	limits := archiveFixtureLimits(t, dir)
	writer, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if _, err := OpenExistingArchiveSnapshot(dir, limits); !errors.Is(err, ErrStoreLocked) {
		t.Fatalf("lock contention did not preserve ErrStoreLocked: %v", err)
	}
}

func TestExistingArchiveSnapshotRejectsUnsafeLeaves(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{"extra-entry", func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "foreign"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"wrong-mode", func(t *testing.T, dir string) {
			if err := os.Chmod(filepath.Join(dir, checkpointFilename), 0o640); err != nil {
				t.Fatal(err)
			}
		}},
		{"hardlink", func(t *testing.T, dir string) {
			target := filepath.Join(filepath.Dir(dir), filepath.Base(dir)+"-hardlink")
			if err := os.Link(filepath.Join(dir, checkpointFilename), target); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Remove(target) })
		}},
		{"symlink", func(t *testing.T, dir string) {
			path := filepath.Join(dir, logFilename)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(filepath.Dir(dir), filepath.Base(dir)+"-log-target")
			if err := os.WriteFile(target, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Remove(target) })
		}},
		{"directory", func(t *testing.T, dir string) {
			path := filepath.Join(dir, logFilename)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{"unix-socket", func(t *testing.T, dir string) {
			path := filepath.Join(dir, logFilename)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			listener, err := net.Listen("unix", path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := archiveActualFixture(t)
			limits := archiveFixtureLimits(t, dir)
			test.mutate(t, dir)
			if _, err := OpenExistingArchiveSnapshot(dir, limits); !errors.Is(err, ErrArchiveExistingUnsafe) {
				t.Fatalf("unsafe leaf returned non-fixed error: %v", err)
			}
		})
	}
}

func TestExistingArchiveSnapshotRevalidateRejectsChangeWithoutUpdatingCache(t *testing.T) {
	dir := archiveActualFixture(t)
	limits := archiveFixtureLimits(t, dir)
	snapshot, err := OpenExistingArchiveSnapshot(dir, limits)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	anchor := snapshot.Anchor()
	checkpointPath := filepath.Join(dir, checkpointFilename)
	raw, err := os.ReadFile(checkpointPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(checkpointPath, append(append([]byte{}, raw...), ' '), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := snapshot.Revalidate(); !errors.Is(err, ErrArchiveExistingUnsafe) {
		t.Fatalf("changed source did not fail with fixed unsafe error: %v", err)
	}
	if got := snapshot.Anchor(); got != anchor {
		t.Fatal("failed Revalidate changed cached Anchor")
	}
}

func TestExistingArchiveSnapshotRejectsInvalidLimitsBeforePathOpen(t *testing.T) {
	tests := []ArchiveExistingReadLimits{
		{MaxLogBytes: 0, MaxEvents: 1},
		{MaxLogBytes: 1, MaxEvents: 0},
		{MaxLogBytes: math.MaxUint64, MaxEvents: 1},
	}
	for _, limits := range tests {
		if _, err := OpenExistingArchiveSnapshot("", limits); !errors.Is(err, ErrArchiveExistingLimit) {
			t.Fatalf("invalid limits did not reject before path: %#v err=%v", limits, err)
		}
	}
}

func TestExistingArchiveSnapshotByteAndEventLimits(t *testing.T) {
	dir := archiveActualFixtureEvents(t, 2)
	limits := archiveFixtureLimits(t, dir)
	byteLimited := limits
	byteLimited.MaxLogBytes--
	if _, err := OpenExistingArchiveSnapshot(dir, byteLimited); !errors.Is(err, ErrArchiveExistingLimit) {
		t.Fatalf("stable byte overage did not return limit: %v", err)
	}
	eventLimited := limits
	eventLimited.MaxEvents--
	if _, err := OpenExistingArchiveSnapshot(dir, eventLimited); !errors.Is(err, ErrArchiveExistingLimit) {
		t.Fatalf("valid proof event did not return limit: %v", err)
	}
}

func TestExistingArchiveSnapshotInvalidProofNeverBecomesLimit(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, string, []EvidenceEvent)
	}{
		{"invalid-json", func(t *testing.T, dir string, events []EvidenceEvent) {
			lines := archiveEventLines(t, dir)
			lines[1] = []byte("{")
			archiveWriteEventLines(t, dir, lines)
		}},
		{"bad-proof-hash", func(t *testing.T, dir string, events []EvidenceEvent) {
			lines := archiveEventLines(t, dir)
			events[1].Hash = strings.Repeat("0", 64)
			lines[1] = archiveEventJSON(t, events[1])
			archiveWriteEventLines(t, dir, lines)
		}},
		{"duplicate-proof-id", func(t *testing.T, dir string, events []EvidenceEvent) {
			lines := archiveEventLines(t, dir)
			events[1].ID = events[0].ID
			lines[1] = archiveEventJSON(t, events[1])
			archiveWriteEventLines(t, dir, lines)
		}},
		{"checkpoint-count-less", func(t *testing.T, dir string, events []EvidenceEvent) {
			archiveWriteCheckpoint(t, dir, checkpoint{Count: 1, LastHash: events[0].Hash})
		}},
		{"checkpoint-exact-head-mismatch", func(t *testing.T, dir string, events []EvidenceEvent) {
			archiveWriteCheckpoint(t, dir, checkpoint{Count: 2, LastHash: genesisHash})
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := archiveActualFixtureEvents(t, 2)
			limits := archiveFixtureLimits(t, dir)
			limits.MaxEvents = 1
			events := archiveEvents(t, dir)
			test.mutate(t, dir, events)
			if _, err := OpenExistingArchiveSnapshot(dir, limits); !errors.Is(err, ErrArchiveExistingUnsafe) {
				t.Fatalf("invalid proof was not unsafe: %v", err)
			}
		})
	}
}

func TestExistingArchiveSnapshotLongerCheckpointIsPrefixOnlyLimit(t *testing.T) {
	dir := archiveActualFixtureEvents(t, 2)
	limits := archiveFixtureLimits(t, dir)
	limits.MaxEvents = 1
	events := archiveEvents(t, dir)
	archiveWriteCheckpoint(t, dir, checkpoint{Count: 3, LastHash: events[1].Hash})
	if _, err := OpenExistingArchiveSnapshot(dir, limits); !errors.Is(err, ErrArchiveExistingLimit) {
		t.Fatalf("stable validated prefix over policy did not return limit: %v", err)
	}
}

func TestArchiveProofWindowRejectsCheckpointMutationAndRebind(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{"bytes", func(t *testing.T, path string) {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			raw[len(raw)-1] ^= 1
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"rebind", func(t *testing.T, path string) {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := archiveActualFixtureEvents(t, 2)
			directory, err := os.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer directory.Close()
			logFile, err := os.Open(filepath.Join(dir, logFilename))
			if err != nil {
				t.Fatal(err)
			}
			defer logFile.Close()
			checkpointFile, err := os.Open(filepath.Join(dir, checkpointFilename))
			if err != nil {
				t.Fatal(err)
			}
			defer checkpointFile.Close()
			logBefore, err := archiveValidateRegular(logFile, false)
			if err != nil {
				t.Fatal(err)
			}
			cpBefore, err := archiveReadCheckpoint(checkpointFile)
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(t, filepath.Join(dir, checkpointFilename))
			if _, err := archiveProofWindowStable(directory, logFile, checkpointFile, logBefore, cpBefore); !errors.Is(err, ErrArchiveExistingUnsafe) {
				t.Fatalf("checkpoint proof-window change was not unsafe: %v", err)
			}
		})
	}
}

func TestExistingArchiveSnapshotRejectsFIFOWithoutWaiting(t *testing.T) {
	dir := archiveActualFixture(t)
	limits := archiveFixtureLimits(t, dir)
	path := filepath.Join(dir, logFilename)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestExistingArchiveSnapshotFIFOHelper$")
	cmd.Env = append(os.Environ(),
		"CHENGWANG_A1_FIFO_HELPER=1",
		"CHENGWANG_A1_FIFO_ROOT="+dir,
		"CHENGWANG_A1_FIFO_MAX_BYTES="+strconv.FormatUint(limits.MaxLogBytes, 10),
		"CHENGWANG_A1_FIFO_MAX_EVENTS="+strconv.FormatUint(limits.MaxEvents, 10),
	)
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("FIFO source open waited: %v", ctx.Err())
	}
	if err != nil {
		t.Fatalf("FIFO helper failed: %v output=%q", err, output)
	}
}

func TestExistingArchiveSnapshotFIFOHelper(t *testing.T) {
	if os.Getenv("CHENGWANG_A1_FIFO_HELPER") != "1" {
		return
	}
	maxBytes, err := strconv.ParseUint(os.Getenv("CHENGWANG_A1_FIFO_MAX_BYTES"), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	maxEvents, err := strconv.ParseUint(os.Getenv("CHENGWANG_A1_FIFO_MAX_EVENTS"), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	limits := ArchiveExistingReadLimits{MaxLogBytes: maxBytes, MaxEvents: maxEvents}
	if _, err := OpenExistingArchiveSnapshot(os.Getenv("CHENGWANG_A1_FIFO_ROOT"), limits); !errors.Is(err, ErrArchiveExistingUnsafe) {
		t.Fatalf("FIFO was not fixed unsafe: %v", err)
	}
}

func archiveActualFixture(t *testing.T) string {
	return archiveActualFixtureEvents(t, 1)
}

func archiveActualFixtureEvents(t *testing.T, eventCount int) string {
	t.Helper()
	base := os.Getenv("CHENGWANG_A1_ACTUALFS_ROOT")
	if base == "" || !filepath.IsAbs(base) || filepath.Clean(base) != base {
		t.Fatal("CHENGWANG_A1_ACTUALFS_ROOT must name the dedicated absolute ext4, XFS, or tmpfs test root")
	}
	baseFile, err := os.Open(base)
	if err != nil {
		t.Fatal(err)
	}
	class, ok := archiveNativeClass(baseFile)
	closeErr := baseFile.Close()
	if closeErr != nil || !ok {
		t.Fatalf("actual-fs root is outside the closed native set: class=%d close=%v", class, closeErr)
	}
	if class == nativefs.LinuxTmpfs {
		t.Log("tmpfs exercises semantics only and is not durability evidence")
	}
	dir, err := os.MkdirTemp(base, "a1-evidence-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < eventCount; i++ {
		if _, err := store.Append(testEvent("archive.snapshot.fixture." + strconv.Itoa(i))); err != nil {
			_ = store.Close()
			t.Fatal(err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	return dir
}

func archiveEventLines(t *testing.T, dir string) [][]byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, logFilename))
	if err != nil {
		t.Fatal(err)
	}
	trimmed := bytes.TrimSuffix(raw, []byte{'\n'})
	return bytes.Split(trimmed, []byte{'\n'})
}

func archiveEvents(t *testing.T, dir string) []EvidenceEvent {
	t.Helper()
	lines := archiveEventLines(t, dir)
	events := make([]EvidenceEvent, len(lines))
	for i := range lines {
		if err := strictUnmarshal(lines[i], &events[i]); err != nil {
			t.Fatal(err)
		}
	}
	return events
}

func archiveEventJSON(t *testing.T, event EvidenceEvent) []byte {
	t.Helper()
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func archiveWriteEventLines(t *testing.T, dir string, lines [][]byte) {
	t.Helper()
	raw := append(bytes.Join(lines, []byte{'\n'}), '\n')
	if err := os.WriteFile(filepath.Join(dir, logFilename), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func archiveWriteCheckpoint(t *testing.T, dir string, cp checkpoint) {
	t.Helper()
	raw, err := json.Marshal(cp)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, checkpointFilename), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func archiveFixtureBytes(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	result := make(map[string][]byte, len(names))
	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		result[name] = bytes.Clone(raw)
	}
	return result
}

func archiveFixtureLimits(t *testing.T, dir string) ArchiveExistingReadLimits {
	t.Helper()
	logInfo, err := os.Stat(filepath.Join(dir, logFilename))
	if err != nil {
		t.Fatal(err)
	}
	if logInfo.Size() <= 0 {
		t.Fatalf("fixture log size: %d", logInfo.Size())
	}
	raw, err := os.ReadFile(filepath.Join(dir, checkpointFilename))
	if err != nil {
		t.Fatal(err)
	}
	var cp checkpoint
	if err := strictUnmarshal(raw, &cp); err != nil || cp.Count == 0 {
		t.Fatalf("fixture checkpoint: count=%d err=%v", cp.Count, err)
	}
	return ArchiveExistingReadLimits{MaxLogBytes: uint64(logInfo.Size()), MaxEvents: cp.Count}
}
