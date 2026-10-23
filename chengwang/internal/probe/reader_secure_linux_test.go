//go:build linux

package probe

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func secureTestOwner() SecureFileOwner {
	return SecureFileOwner{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}
}

func secureTestFixture(t *testing.T) (string, SecureReadOptions) {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(directory, spoolSegmentsDirectory), 0o700); err != nil {
		t.Fatal(err)
	}
	owner := secureTestOwner()
	return directory, SecureReadOptions{ReadOptions: ReadOptions{Catalog: testSpoolCatalog(t), Now: time.Now().UTC(), Limit: MaximumReadResults}, OwnerUID: owner.UID, OwnerGID: owner.GID}
}

func secureTestAdd(t *testing.T, directory string, at time.Time, id string) string {
	t.Helper()
	segment := makeTestSegment(t, validTestResult(at, id))
	name := spoolSegmentFileName(segment)
	writeRawTestSegment(t, directory, segment, name)
	return filepath.Join(directory, spoolSegmentsDirectory, name)
}

func secureTestReject(t *testing.T, directory string, options SecureReadOptions, wanted error) {
	t.Helper()
	report, err := ReadStoreSecure(context.Background(), directory, options)
	if !errors.Is(err, wanted) || report.Healthy || report.Results != nil || report.Returned != 0 {
		t.Fatal("secure read did not reject with the fixed error and zero usable samples")
	}
}

func secureTestCatalog(t *testing.T, directory string) string {
	t.Helper()
	raw, err := json.Marshal(testSpoolCatalog(t))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "catalog.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func secureTestTree(t *testing.T, directory string) map[string]string {
	t.Helper()
	values := make(map[string]string)
	err := filepath.WalkDir(directory, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		value := fmt.Sprintf("%v:%d", info.Mode(), info.Size())
		if !entry.IsDir() {
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			digest := sha256.Sum256(raw)
			value += ":" + hex.EncodeToString(digest[:])
		}
		name, err := filepath.Rel(directory, path)
		if err != nil {
			return err
		}
		values[name] = value
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return values
}

func TestProbeSecureP1StoreHealthyReadOnly(t *testing.T) {
	dir, options := secureTestFixture(t)
	secureTestAdd(t, dir, options.Now.Add(-time.Second), "healthy")
	before := secureTestTree(t, dir)
	report, err := ReadStoreSecure(context.Background(), dir, options)
	if err != nil || !report.Healthy || report.ValidTotal != 1 || report.EligibleTotal != 1 || report.Returned != 1 || report.ScannedEntries != 1 || report.Truncated {
		t.Fatal("secure healthy native read did not produce exact counts")
	}
	left, _ := json.Marshal(before)
	right, _ := json.Marshal(secureTestTree(t, dir))
	if !bytes.Equal(left, right) {
		t.Fatal("secure reader changed spool names, bytes or permissions")
	}
}

func TestProbeSecureP1StoreWriterLockDoesNotBlockRead(t *testing.T) {
	dir, options := secureTestFixture(t)
	store, err := OpenStore(dir, options.Catalog, StoreLimits{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Append(validTestResult(options.Now.Add(-time.Second), "locked-writer")); err != nil {
		t.Fatal(err)
	}
	report, err := ReadStoreSecure(context.Background(), dir, options)
	if err != nil || !report.Healthy || report.Returned != 1 {
		t.Fatal("secure read incorrectly required the live writer lock")
	}
}

func TestProbeSecureP1StoreExpiredCountsAreNotCorruption(t *testing.T) {
	dir, options := secureTestFixture(t)
	secureTestAdd(t, dir, options.Now.Add(-3*time.Hour), "expired")
	secureTestAdd(t, dir, options.Now.Add(-time.Second), "fresh")
	report, err := ReadStoreSecure(context.Background(), dir, options)
	if err != nil || !report.Healthy || report.ValidTotal != 2 || report.ExpiredTotal != 1 || report.EligibleTotal != 1 || report.Returned != 1 || report.Rejected != 0 || report.Truncated {
		t.Fatal("normal expiry was hidden, miscounted or marked corrupt")
	}
	old, err := ReadStore(dir, options.ReadOptions)
	if err != nil || old.Rejected != 1 || old.Healthy {
		t.Fatal("historical reader expiry contract unexpectedly changed")
	}
}

func TestProbeSecureP1StoreHistoricalEligibilityCounts(t *testing.T) {
	dir, options := secureTestFixture(t)
	secureTestAdd(t, dir, options.Now.Add(-3*time.Hour), "expired-history")
	options.IncludeExpired = true
	report, err := ReadStoreSecure(context.Background(), dir, options)
	if err != nil || !report.Healthy || report.ValidTotal != 1 || report.ExpiredTotal != 1 || report.EligibleTotal != 1 || report.Returned != 1 {
		t.Fatal("historical secure eligibility did not preserve explicit expiry counts")
	}
}

func TestProbeSecureP1StoreGlobalLimitIsActuallyTruncated(t *testing.T) {
	dir, options := secureTestFixture(t)
	for i := 0; i < 201; i++ {
		secureTestAdd(t, dir, options.Now.Add(-time.Second).Add(time.Duration(i)*time.Millisecond), fmt.Sprintf("limit-%03d", i))
	}
	report, err := ReadStoreSecure(context.Background(), dir, options)
	if err != nil || !report.Healthy || report.ValidTotal != 201 || report.EligibleTotal != 201 || report.Returned != 200 || !report.Truncated || report.Results[0].RunID != "limit-001" {
		t.Fatal("global retained-result truncation was inferred or concealed")
	}
}

func TestProbeSecureP1StoreContentRejectionHasNoFilename(t *testing.T) {
	dir, options := secureTestFixture(t)
	secureTestAdd(t, dir, options.Now.Add(-time.Second), "good-with-rejection")
	name := filepath.Join(dir, spoolSegmentsDirectory, "credential-sentinel.json")
	if os.WriteFile(name, []byte(`{"schema":"unknown-sensitive-value"}`), 0o600) != nil {
		t.Fatal("cannot create private rejected content")
	}
	report, err := ReadStoreSecure(context.Background(), dir, options)
	if err != nil || report.Healthy || report.Rejected != 1 || report.ValidTotal != 1 || report.Returned != 1 || len(report.Issues) != 1 || report.Issues[0].File != "" {
		t.Fatal("secure content rejection did not preserve safe explicit counts")
	}
	raw, _ := json.Marshal(report)
	if bytes.Contains(raw, []byte("sentinel")) || bytes.Contains(raw, []byte("sensitive-value")) {
		t.Fatal("secure rejection disclosed a name or raw content")
	}
}

func TestProbeSecureP1StoreWrongOwnerRejected(t *testing.T) {
	dir, options := secureTestFixture(t)
	options.OwnerUID++
	secureTestReject(t, dir, options, ErrSecureUnsafe)
}

func TestProbeSecureP1StoreWrongGroupRejected(t *testing.T) {
	dir, options := secureTestFixture(t)
	options.OwnerGID++
	secureTestReject(t, dir, options, ErrSecureUnsafe)
}

func TestProbeSecureP1StoreLooseDirectoryRejectedWithoutRepair(t *testing.T) {
	dir, options := secureTestFixture(t)
	if os.Chmod(dir, 0o750) != nil {
		t.Fatal("cannot arrange directory mode")
	}
	secureTestReject(t, dir, options, ErrSecureUnsafe)
	info, err := os.Stat(dir)
	if err != nil || info.Mode().Perm() != 0o750 {
		t.Fatal("secure reader repaired directory permissions")
	}
}

func TestProbeSecureP1StoreLooseSegmentRejectedWithoutRepair(t *testing.T) {
	dir, options := secureTestFixture(t)
	path := secureTestAdd(t, dir, options.Now.Add(-time.Second), "loose-file")
	if os.Chmod(path, 0o640) != nil {
		t.Fatal("cannot arrange file mode")
	}
	secureTestReject(t, dir, options, ErrSecureUnsafe)
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o640 {
		t.Fatal("secure reader repaired file permissions")
	}
}

func TestProbeSecureP1StoreHardlinkRejected(t *testing.T) {
	dir, options := secureTestFixture(t)
	path := secureTestAdd(t, dir, options.Now.Add(-time.Second), "linked")
	if os.Link(path, filepath.Join(dir, "outside-link")) != nil {
		t.Fatal("cannot create owned hard link")
	}
	secureTestReject(t, dir, options, ErrSecureUnsafe)
}

func TestProbeSecureP1StoreSegmentSymlinkRejected(t *testing.T) {
	dir, options := secureTestFixture(t)
	path := secureTestAdd(t, dir, options.Now.Add(-time.Second), "symlink")
	target := filepath.Join(dir, "held-original")
	if os.Rename(path, target) != nil || os.Symlink(target, path) != nil {
		t.Fatal("cannot arrange owned symlink")
	}
	secureTestReject(t, dir, options, ErrSecureUnsafe)
}

func TestProbeSecureP1StoreSegmentsDirectorySymlinkRejected(t *testing.T) {
	dir, options := secureTestFixture(t)
	path := filepath.Join(dir, spoolSegmentsDirectory)
	target := filepath.Join(dir, "original-segments")
	if os.Rename(path, target) != nil || os.Symlink(target, path) != nil {
		t.Fatal("cannot arrange segments symlink")
	}
	secureTestReject(t, dir, options, ErrSecureUnsafe)
}

func TestProbeSecureP1StoreAncestorSymlinkRejected(t *testing.T) {
	dir, options := secureTestFixture(t)
	link := filepath.Join(t.TempDir(), "spool-alias")
	if os.Symlink(dir, link) != nil {
		t.Fatal("cannot arrange ancestor symlink")
	}
	secureTestReject(t, link, options, ErrSecureUnsafe)
}

func TestProbeSecureP1StoreFIFOIsBounded(t *testing.T) {
	if os.Getenv("CHENGWANG_TEST_SECURE_FIFO") == "1" {
		dir := os.Getenv("CHENGWANG_TEST_SECURE_DIR")
		owner := secureTestOwner()
		report, err := ReadStoreSecure(context.Background(), dir, SecureReadOptions{ReadOptions: ReadOptions{Catalog: testSpoolCatalog(t)}, OwnerUID: owner.UID, OwnerGID: owner.GID})
		if !errors.Is(err, ErrSecureUnsafe) || report.Results != nil {
			t.Fatal("native FIFO did not fail closed")
		}
		fmt.Println("SECURE_FIFO_REJECTED")
		return
	}
	dir, _ := secureTestFixture(t)
	path := filepath.Join(dir, spoolSegmentsDirectory, "00000000000000000001-0123456789abcdef.json")
	if syscall.Mkfifo(path, 0o600) != nil {
		t.Fatal("cannot create private native FIFO")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestProbeSecureP1StoreFIFOIsBounded$", "-test.count=1")
	command.Env = append(os.Environ(), "CHENGWANG_TEST_SECURE_FIFO=1", "CHENGWANG_TEST_SECURE_DIR="+dir)
	raw, err := command.CombinedOutput()
	if err != nil || ctx.Err() != nil || bytes.Count(raw, []byte("SECURE_FIFO_REJECTED")) != 1 {
		t.Fatal("native cross-process FIFO rejection did not complete within its bound")
	}
}

func TestProbeSecureP1StoreOversizeFailsWithNoPartialView(t *testing.T) {
	dir, options := secureTestFixture(t)
	secureTestAdd(t, dir, options.Now.Add(-time.Second), "valid-before-oversize")
	path := filepath.Join(dir, spoolSegmentsDirectory, "oversize.json")
	if os.WriteFile(path, bytes.Repeat([]byte("x"), int(MaximumSpoolSegmentBytes)+1), 0o600) != nil {
		t.Fatal("cannot create bounded oversized segment")
	}
	secureTestReject(t, dir, options, ErrSecureLimit)
}

func TestProbeSecureP1StoreAbsoluteEnumerationCountsAreReal(t *testing.T) {
	dir, options := secureTestFixture(t)
	for i := 0; i < 4300; i++ {
		if os.WriteFile(filepath.Join(dir, spoolSegmentsDirectory, fmt.Sprintf("entry-%04d.json", i)), []byte("x"), 0o600) != nil {
			t.Fatal("cannot populate bounded entry-overflow fixture")
		}
	}
	report, err := ReadStoreSecure(context.Background(), dir, options)
	if !errors.Is(err, ErrSecureLimit) || report.ScannedEntries != 4224 || report.TotalEntries != 4224 || report.Results != nil || report.Healthy {
		t.Fatal("native 128-entry batches did not report actual overscan count")
	}
}

func TestProbeSecureP1StoreByteBudgetCountsAreReal(t *testing.T) {
	dir, options := secureTestFixture(t)
	for _, name := range []string{"a.json", "b.json"} {
		if os.WriteFile(filepath.Join(dir, spoolSegmentsDirectory, name), bytes.Repeat([]byte("x"), 40000), 0o600) != nil {
			t.Fatal("cannot populate byte-budget fixture")
		}
	}
	options.MaxBytes = MaximumSpoolSegmentBytes
	report, err := ReadStoreSecure(context.Background(), dir, options)
	if !errors.Is(err, ErrSecureLimit) || report.TotalBytes != 80000 || report.ScannedEntries != 2 || report.Results != nil {
		t.Fatal("byte limit used an inferred limit+1 sentinel rather than observed sizes")
	}
}

func TestProbeSecureP1StoreCanceledContextNoIO(t *testing.T) {
	_, options := secureTestFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	report, err := ReadStoreSecure(ctx, "/missing-secure-read-sentinel", options)
	if !errors.Is(err, context.Canceled) || report.Results != nil {
		t.Fatal("cancellation identity was lost before filesystem access")
	}
}

func TestProbeSecureP1StoreExpiredDeadlineNoIO(t *testing.T) {
	_, options := secureTestFixture(t)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	_, err := ReadStoreSecure(ctx, "/missing-secure-read-sentinel", options)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("deadline identity was lost before filesystem access")
	}
}

func TestProbeSecureP1HeldFileRejectsNamedInodeReplacement(t *testing.T) {
	dir, options := secureTestFixture(t)
	path := secureTestAdd(t, dir, options.Now.Add(-time.Second), "named-replacement")
	parts, _ := securePathParts(filepath.Dir(path))
	chain, err := openSecureDirectories(context.Background(), parts, secureTestOwner(), secureStateDirectory)
	if err != nil {
		t.Fatal("cannot open native held parent")
	}
	defer chain.close()
	held, err := openSecureRegular(context.Background(), chain.dirs[len(chain.dirs)-1], filepath.Base(path), secureTestOwner(), false)
	if err != nil {
		t.Fatal("cannot hold original native file")
	}
	defer held.file.Close()
	raw, _ := os.ReadFile(path)
	pending := filepath.Join(dir, "replacement")
	if os.WriteFile(pending, raw, 0o600) != nil || os.Rename(pending, path) != nil {
		t.Fatal("cannot replace named file with identical bytes")
	}
	if _, err := held.read(context.Background(), MaximumSpoolSegmentBytes); !errors.Is(err, ErrSecureChanged) {
		t.Fatal("held/native named inode mismatch was accepted")
	}
}

func TestProbeSecureP1HeldFileRejectsInPlaceMutation(t *testing.T) {
	dir, options := secureTestFixture(t)
	path := secureTestAdd(t, dir, options.Now.Add(-time.Second), "in-place")
	parts, _ := securePathParts(filepath.Dir(path))
	chain, err := openSecureDirectories(context.Background(), parts, secureTestOwner(), secureStateDirectory)
	if err != nil {
		t.Fatal("cannot open native held parent")
	}
	defer chain.close()
	held, err := openSecureRegular(context.Background(), chain.dirs[len(chain.dirs)-1], filepath.Base(path), secureTestOwner(), false)
	if err != nil {
		t.Fatal("cannot hold original native file")
	}
	defer held.file.Close()
	raw, _ := os.ReadFile(path)
	raw[0] = ' '
	if os.WriteFile(path, raw, 0o600) != nil {
		t.Fatal("cannot mutate owned native segment")
	}
	if _, err := held.read(context.Background(), MaximumSpoolSegmentBytes); !errors.Is(err, ErrSecureChanged) {
		t.Fatal("native held metadata mutation was accepted")
	}
}

func TestProbeSecureP1DirectoryRejectsParentReplacement(t *testing.T) {
	dir, _ := secureTestFixture(t)
	parts, _ := securePathParts(dir)
	chain, err := openSecureDirectories(context.Background(), parts, secureTestOwner(), secureStateDirectory)
	if err != nil {
		t.Fatal("cannot hold native directory")
	}
	defer chain.close()
	if os.Rename(dir, dir+"-old") != nil || os.Mkdir(dir, 0o700) != nil {
		t.Fatal("cannot replace owned directory")
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir + "-old") })
	if !errors.Is(chain.verify(context.Background()), ErrSecureChanged) {
		t.Fatal("held parent replacement was accepted")
	}
}

func TestProbeSecureP1DirectoryRejectsEntryMutation(t *testing.T) {
	dir, _ := secureTestFixture(t)
	parts, _ := securePathParts(dir)
	chain, err := openSecureDirectories(context.Background(), parts, secureTestOwner(), secureStateDirectory)
	if err != nil {
		t.Fatal("cannot hold native directory")
	}
	defer chain.close()
	if os.WriteFile(filepath.Join(dir, "changed-entry"), []byte("x"), 0o600) != nil {
		t.Fatal("cannot mutate owned directory")
	}
	if !errors.Is(chain.verify(context.Background()), ErrSecureChanged) {
		t.Fatal("native directory change was accepted")
	}
}

func TestProbeSecureP1HeldReadHonorsCancellation(t *testing.T) {
	dir, options := secureTestFixture(t)
	path := secureTestAdd(t, dir, options.Now.Add(-time.Second), "held-cancel")
	parts, _ := securePathParts(filepath.Dir(path))
	chain, err := openSecureDirectories(context.Background(), parts, secureTestOwner(), secureStateDirectory)
	if err != nil {
		t.Fatal("cannot hold native parent")
	}
	defer chain.close()
	held, err := openSecureRegular(context.Background(), chain.dirs[len(chain.dirs)-1], filepath.Base(path), secureTestOwner(), false)
	if err != nil {
		t.Fatal("cannot hold native segment")
	}
	defer held.file.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := held.read(ctx, MaximumSpoolSegmentBytes); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation after actual FD acquisition was not observed")
	}
}

func TestProbeSecureP1StoreDoesNotLeakDescriptors(t *testing.T) {
	dir, options := secureTestFixture(t)
	secureTestAdd(t, dir, options.Now.Add(-time.Second), "descriptor-bounded")
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal("native descriptor accounting unavailable")
	}
	for i := 0; i < 32; i++ {
		if _, err := ReadStoreSecure(context.Background(), dir, options); err != nil {
			t.Fatal("repeated native secure read failed")
		}
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(after) > len(before)+2 {
		t.Fatal("secure native reader leaked held descriptors")
	}
}

func TestProbeSecureP1CatalogValidBytesAndNoMutation(t *testing.T) {
	dir := t.TempDir()
	path := secureTestCatalog(t, dir)
	before, _ := os.ReadFile(path)
	catalog, err := ReadCatalogSecure(context.Background(), path, secureTestOwner())
	after, _ := os.ReadFile(path)
	if err != nil || catalog.Digest != testSpoolCatalog(t).Digest || !bytes.Equal(before, after) {
		t.Fatal("secure catalog did not load original immutable content")
	}
}

func TestProbeSecureP1CatalogRejectsSymlinkAndHardlink(t *testing.T) {
	dir := t.TempDir()
	path := secureTestCatalog(t, dir)
	link := filepath.Join(dir, "catalog-link.json")
	if os.Symlink(path, link) != nil {
		t.Fatal("cannot arrange catalog symlink")
	}
	if _, err := ReadCatalogSecure(context.Background(), link, secureTestOwner()); !errors.Is(err, ErrSecureUnsafe) {
		t.Fatal("catalog symlink accepted")
	}
	if os.Remove(link) != nil || os.Link(path, link) != nil {
		t.Fatal("cannot arrange catalog hardlink")
	}
	if _, err := ReadCatalogSecure(context.Background(), path, secureTestOwner()); !errors.Is(err, ErrSecureUnsafe) {
		t.Fatal("catalog hardlink accepted")
	}
}

func TestProbeSecureP1CatalogRejectsPermissionsAndRawErrors(t *testing.T) {
	dir := t.TempDir()
	path := secureTestCatalog(t, dir)
	if os.Chmod(path, 0o644) != nil {
		t.Fatal("cannot arrange unsafe catalog mode")
	}
	if _, err := ReadCatalogSecure(context.Background(), path, secureTestOwner()); !errors.Is(err, ErrSecureUnsafe) {
		t.Fatal("unsafe catalog mode accepted")
	}
	if os.Chmod(path, 0o600) != nil || os.WriteFile(path, []byte(`{"credential-sentinel":"private-sensitive-value"}`), 0o600) != nil {
		t.Fatal("cannot arrange malformed private catalog")
	}
	_, err := ReadCatalogSecure(context.Background(), path, secureTestOwner())
	if !errors.Is(err, ErrSecureInvalid) || strings.Contains(err.Error(), "sentinel") || strings.Contains(err.Error(), dir) {
		t.Fatal("catalog error was not the fixed safe enum")
	}
}

func TestProbeSecureP1CatalogRootGroupMetadataPolicy(t *testing.T) {
	owner := SecureFileOwner{UID: 10001, GID: 10001}
	file := syscall.Stat_t{Mode: syscall.S_IFREG | 0o640, Uid: 0, Gid: 10001, Nlink: 1, Size: 10}
	directory := syscall.Stat_t{Mode: syscall.S_IFDIR | 0o750, Uid: 0, Gid: 10001}
	if secureRegularMetadata(file, owner, true) != nil || secureDirectoryMetadata(directory, owner, secureCatalogDirectory) != nil {
		t.Fatal("explicit root-owned group-readable catalog policy rejected")
	}
	if secureRegularMetadata(file, owner, false) == nil {
		t.Fatal("catalog policy widened regular spool custody")
	}
	file.Gid++
	if secureRegularMetadata(file, owner, true) == nil {
		t.Fatal("foreign catalog group accepted")
	}
}

func TestProbeSecureP1InvalidInputsHaveClosedErrors(t *testing.T) {
	dir, options := secureTestFixture(t)
	if _, err := ReadStoreSecure(nil, dir, options); !errors.Is(err, ErrSecureInvalid) {
		t.Fatal("nil context was accepted")
	}
	for _, path := range []string{"relative-private-sentinel", dir + "/", dir + "/../other", " " + dir, "/"} {
		_, err := ReadStoreSecure(context.Background(), path, options)
		if !errors.Is(err, ErrSecureInvalid) {
			t.Fatal("noncanonical secure path was accepted")
		}
	}
	options.Limit = 201
	secureTestReject(t, dir, options, ErrSecureInvalid)
}

func TestProbeSecureP1FilesystemRejectsProcWithoutFallback(t *testing.T) {
	file, err := os.Open("/proc")
	if err != nil {
		t.Fatal("native proc filesystem unavailable")
	}
	defer file.Close()
	if !errors.Is(secureFilesystem(file, false), ErrSecureUnsupported) {
		t.Fatal("special filesystem was accepted for actual probe data")
	}
}
