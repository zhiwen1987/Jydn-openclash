package probe

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const StateValidationSchemaV1 = "chengwang.probe-state-validation/v1"

// StateValidationOptions bounds a read-only validation of one stopped spool
// and start-ledger snapshot. Validation holds both existing writer locks via
// read-only file descriptors, but never creates or writes a file, removes an
// interrupted file, compacts retention, or repairs state.
type StateValidationOptions struct {
	Catalog Catalog
	// ExpectedLedgerWriterDirectory is the absolute path seen by the runtime
	// writer whose digest is embedded in ledger snapshots. It permits validation
	// of a staged copy from a different host path without confusing host and
	// container namespaces. When empty, LedgerDirectory itself is used.
	ExpectedLedgerWriterDirectory string
	Now                           time.Time
	MaxFutureSkew                 time.Duration
	SpoolMaxEntries               int
	SpoolMaxBytes                 int64
	LedgerMaxEntries              int
	LedgerMaxBytes                int64
	ExpectedOwnerUID              uint64
	ExpectedOwnerGID              uint64
	EnforceExpectedOwner          bool
}

// StateValidationReport contains only structural and semantic counts. Its
// digest binds the exact bytes and relative paths read from both state trees;
// it is not a runtime-health or network-availability claim.
type StateValidationReport struct {
	Schema                   string `json:"schema"`
	CatalogDigest            string `json:"catalogDigest"`
	SnapshotDigest           string `json:"snapshotDigest"`
	ReadPathDigest           string `json:"readPathDigest"`
	LedgerWriterPathDigest   string `json:"ledgerWriterPathDigest"`
	RelationshipScope        string `json:"relationshipScope"`
	SpoolResults             int    `json:"spoolResults"`
	LedgerSnapshots          int    `json:"ledgerSnapshots"`
	LatestSequence           uint64 `json:"latestSequence"`
	LatestStarts             int    `json:"latestStarts"`
	LatestInFlight           int    `json:"latestInFlight"`
	LatestSettled            int    `json:"latestSettled"`
	LatestRateLimits         int    `json:"latestRateLimits"`
	AdvisoryOnly             bool   `json:"advisoryOnly"`
	ReadOnlyValidation       bool   `json:"readOnlyValidation"`
	SecurityMetadataVerified bool   `json:"securityMetadataVerified"`
	OwnerUID                 uint64 `json:"ownerUid"`
	OwnerGID                 uint64 `json:"ownerGid"`
	ExpectedOwnerUID         uint64 `json:"expectedOwnerUid"`
	ExpectedOwnerGID         uint64 `json:"expectedOwnerGid"`
	MissingRetainedEvidence  int    `json:"missingRetainedEvidence"`
	RelationshipComplete     bool   `json:"relationshipComplete"`
}

type stateTreeEntry struct {
	relative string
	digest   string
	size     int64
	mode     os.FileMode
	owner    uint64
	group    uint64
	nlink    uint64
	identity string
}

// ValidateStateSnapshot strictly validates one spool and ledger generation.
// The caller must stop every writer before taking the snapshot. A second tree
// fingerprint detects changes made while validation is in progress.
func ValidateStateSnapshot(spoolDirectory, ledgerDirectory string, options StateValidationOptions) (StateValidationReport, error) {
	binding, err := bindCatalog(options.Catalog)
	if err != nil {
		return StateValidationReport{}, fmt.Errorf("bind state catalog: %w", err)
	}
	if options.Now.IsZero() {
		options.Now = time.Now().UTC()
	}
	if options.Now.UnixNano() < 0 {
		return StateValidationReport{}, errors.New("state validation current time is invalid")
	}
	if options.MaxFutureSkew == 0 {
		options.MaxFutureSkew = defaultFutureSkew
	}
	if options.MaxFutureSkew < 0 || options.MaxFutureSkew > 10*time.Minute {
		return StateValidationReport{}, errors.New("state validation future skew must be between zero and ten minutes")
	}
	spoolMaxEntries, spoolMaxBytes, err := normalizeSpoolLimits(options.SpoolMaxEntries, options.SpoolMaxBytes)
	if err != nil {
		return StateValidationReport{}, err
	}
	ledgerMaxEntries, ledgerMaxBytes, err := normalizeStartLedgerLimits(options.LedgerMaxEntries, options.LedgerMaxBytes)
	if err != nil {
		return StateValidationReport{}, err
	}
	spoolAbs, ledgerAbs, ledgerWriterAbs, err := validateStateRoots(spoolDirectory, ledgerDirectory, options.ExpectedLedgerWriterDirectory)
	if err != nil {
		return StateValidationReport{}, err
	}

	before, owner, group, err := inspectStateTrees(spoolAbs, ledgerAbs, spoolMaxEntries, spoolMaxBytes, ledgerMaxBytes)
	if err != nil {
		return StateValidationReport{}, err
	}
	securityMetadataVerified := stateSecurityMetadataAvailable()
	if options.EnforceExpectedOwner {
		if !securityMetadataVerified {
			return StateValidationReport{}, errors.New("state ownership metadata is unavailable on this platform")
		}
		if owner != options.ExpectedOwnerUID || group != options.ExpectedOwnerGID {
			return StateValidationReport{}, fmt.Errorf("state owner is uid=%d gid=%d, want uid=%d gid=%d", owner, group, options.ExpectedOwnerUID, options.ExpectedOwnerGID)
		}
	}
	var lockReleases []func() error
	defer func() {
		for index := len(lockReleases) - 1; index >= 0; index-- {
			_ = lockReleases[index]()
		}
	}()
	for _, lockPath := range []string{filepath.Join(spoolAbs, spoolLockFilename), filepath.Join(ledgerAbs, startLedgerLockFilename)} {
		release, err := acquireStateValidationLock(lockPath)
		if err != nil {
			return StateValidationReport{}, fmt.Errorf("state writer must be stopped: %w", err)
		}
		lockReleases = append(lockReleases, release)
	}

	spoolScan, err := scanSpoolSegments(filepath.Join(spoolAbs, spoolSegmentsDirectory), binding, options.Now, options.MaxFutureSkew, true, false, spoolMaxEntries, spoolMaxBytes)
	if err != nil {
		return StateValidationReport{}, fmt.Errorf("validate probe spool: %w", err)
	}
	if len(spoolScan.issues) != 0 {
		issue := spoolScan.issues[0]
		return StateValidationReport{}, fmt.Errorf("invalid probe spool entry %q: %s", issue.File, issue.Reason)
	}
	ledgerSnapshotDir := filepath.Join(ledgerAbs, startLedgerSnapshotsDir)
	latest, ledgerFiles, _, err := readStartLedgerSnapshots(ledgerSnapshotDir, binding, digestStartLedgerDirectory(ledgerWriterAbs), ledgerMaxEntries, ledgerMaxBytes, options.Now)
	if err != nil {
		return StateValidationReport{}, fmt.Errorf("validate start ledger: %w", err)
	}
	if latest == nil {
		return StateValidationReport{}, errors.New("start ledger contains no durable snapshot")
	}
	if err := validateStartLedgerEvolution(ledgerSnapshotDir, binding, digestStartLedgerDirectory(ledgerWriterAbs), ledgerMaxEntries, ledgerMaxBytes, options.Now); err != nil {
		return StateValidationReport{}, err
	}
	missingRetainedEvidence, err := validateLatestStateRelationships(*latest, spoolScan.valid)
	if err != nil {
		return StateValidationReport{}, err
	}

	after, _, _, err := inspectStateTrees(spoolAbs, ledgerAbs, spoolMaxEntries, spoolMaxBytes, ledgerMaxBytes)
	if err != nil {
		return StateValidationReport{}, err
	}
	if !sameStateTree(before, after) {
		return StateValidationReport{}, errors.New("probe state changed while read-only validation was running")
	}

	settled := 0
	inFlight := 0
	for _, entry := range latest.Starts {
		if entry.SettledAt == nil {
			inFlight++
		} else {
			settled++
		}
	}
	return StateValidationReport{
		Schema: StateValidationSchemaV1, CatalogDigest: binding.digest,
		SnapshotDigest:         digestStateTree(before),
		ReadPathDigest:         digestStateReadPaths(spoolAbs, ledgerAbs),
		LedgerWriterPathDigest: digestStartLedgerDirectory(ledgerWriterAbs),
		RelationshipScope:      "latest-ledger-vs-retained-spool",
		SpoolResults:           len(spoolScan.valid),
		LedgerSnapshots:        len(ledgerFiles), LatestSequence: latest.Sequence,
		LatestStarts: len(latest.Starts), LatestInFlight: inFlight,
		LatestSettled: settled, LatestRateLimits: len(latest.RateLimits),
		AdvisoryOnly: true, ReadOnlyValidation: true,
		SecurityMetadataVerified: securityMetadataVerified,
		OwnerUID:                 owner, OwnerGID: group,
		ExpectedOwnerUID: options.ExpectedOwnerUID, ExpectedOwnerGID: options.ExpectedOwnerGID,
		MissingRetainedEvidence: missingRetainedEvidence,
		RelationshipComplete:    missingRetainedEvidence == 0,
	}, nil
}

// validateStartLedgerEvolution checks the retained snapshot window only. Old
// snapshots may have been compacted, so sequence gaps are valid; a decreasing
// commit clock across increasing retained sequences is not.
func validateStartLedgerEvolution(directory string, binding catalogBinding, directoryDigest string, maxEntries int, maxBytes int64, now time.Time) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return fmt.Errorf("list retained start ledger snapshots: %w", err)
	}
	type retained struct {
		sequence uint64
		clock    time.Time
	}
	states := make([]retained, 0, len(entries))
	for _, entry := range entries {
		state, err := readStartLedgerSnapshot(filepath.Join(directory, entry.Name()), binding, directoryDigest, maxEntries, now, maxBytes/2)
		if err != nil {
			return fmt.Errorf("validate retained start ledger evolution: %w", err)
		}
		states = append(states, retained{sequence: state.Sequence, clock: state.LastClock})
	}
	sort.Slice(states, func(i, j int) bool { return states[i].sequence < states[j].sequence })
	for index := 1; index < len(states); index++ {
		if states[index].sequence <= states[index-1].sequence || states[index].clock.Before(states[index-1].clock) {
			return errors.New("retained start ledger sequence or clock is not monotonic")
		}
	}
	return nil
}

func validateStateRoots(spoolDirectory, ledgerDirectory, expectedLedgerWriterDirectory string) (string, string, string, error) {
	if strings.TrimSpace(spoolDirectory) == "" || strings.TrimSpace(ledgerDirectory) == "" {
		return "", "", "", errors.New("spool and ledger directories are required")
	}
	spoolAbs, err := filepath.Abs(spoolDirectory)
	if err != nil {
		return "", "", "", fmt.Errorf("resolve spool directory: %w", err)
	}
	ledgerAbs, err := filepath.Abs(ledgerDirectory)
	if err != nil {
		return "", "", "", fmt.Errorf("resolve ledger directory: %w", err)
	}
	spoolAbs, ledgerAbs = filepath.Clean(spoolAbs), filepath.Clean(ledgerAbs)
	if statePathsOverlap(spoolAbs, ledgerAbs) {
		return "", "", "", errors.New("spool and ledger directories must be independent and non-overlapping")
	}
	if err := rejectSymlinkPathComponents(spoolAbs); err != nil {
		return "", "", "", fmt.Errorf("unsafe spool path: %w", err)
	}
	if err := rejectSymlinkPathComponents(ledgerAbs); err != nil {
		return "", "", "", fmt.Errorf("unsafe ledger path: %w", err)
	}
	ledgerWriterAbs := ledgerAbs
	if expectedLedgerWriterDirectory != "" {
		if expectedLedgerWriterDirectory != strings.TrimSpace(expectedLedgerWriterDirectory) || !filepath.IsAbs(expectedLedgerWriterDirectory) {
			return "", "", "", errors.New("expected ledger writer directory must be a clean absolute path")
		}
		ledgerWriterAbs = filepath.Clean(expectedLedgerWriterDirectory)
		if ledgerWriterAbs != expectedLedgerWriterDirectory {
			return "", "", "", errors.New("expected ledger writer directory must be a clean absolute path")
		}
	}
	return spoolAbs, ledgerAbs, ledgerWriterAbs, nil
}

func statePathsOverlap(first, second string) bool {
	for _, pair := range [][2]string{{first, second}, {second, first}} {
		relative, err := filepath.Rel(pair[0], pair[1])
		if err == nil && (relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))) {
			return true
		}
	}
	return false
}

func inspectStateTrees(spoolRoot, ledgerRoot string, spoolMaxEntries int, spoolMaxBytes, ledgerMaxBytes int64) ([]stateTreeEntry, uint64, uint64, error) {
	var all []stateTreeEntry
	var owner uint64
	var group uint64
	ownerSet := false
	for _, tree := range []struct {
		label, root string
		allowed     map[string]bool
		maxFiles    int
		maxBytes    int64
	}{
		{"spool", spoolRoot, map[string]bool{spoolLockFilename: true, spoolSegmentsDirectory: true}, spoolMaxEntries + 3, spoolMaxBytes + MaximumSpoolSegmentBytes},
		{"ledger", ledgerRoot, map[string]bool{startLedgerLockFilename: true, startLedgerSnapshotsDir: true}, maximumLedgerSnapshotFiles + 3, ledgerMaxBytes + MinimumStartLedgerBytes},
	} {
		entries, treeOwner, treeGroup, err := inspectStateTree(tree.label, tree.root, tree.allowed, tree.maxFiles, tree.maxBytes)
		if err != nil {
			return nil, 0, 0, err
		}
		if stateSecurityMetadataAvailable() {
			if ownerSet && (owner != treeOwner || group != treeGroup) {
				return nil, 0, 0, errors.New("spool and ledger state have different owners")
			}
			owner, group, ownerSet = treeOwner, treeGroup, true
		}
		all = append(all, entries...)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].relative < all[j].relative })
	return all, owner, group, nil
}

func inspectStateTree(label, root string, allowedRoot map[string]bool, maxFiles int, maxBytes int64) ([]stateTreeEntry, uint64, uint64, error) {
	rootInfo, err := os.Lstat(root)
	if err != nil || rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return nil, 0, 0, fmt.Errorf("%s state root must be a real directory", label)
	}
	rootOwner, rootGroup, _, err := validateStateSecurity(rootInfo, true)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("unsafe %s state root: %w", label, err)
	}
	rootEntries, err := os.ReadDir(root)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("list %s state root: %w", label, err)
	}
	found := make(map[string]bool, len(rootEntries))
	for _, entry := range rootEntries {
		if !allowedRoot[entry.Name()] {
			return nil, 0, 0, fmt.Errorf("unexpected %s state root entry %q", label, entry.Name())
		}
		found[entry.Name()] = true
	}
	for required := range allowedRoot {
		if !found[required] {
			return nil, 0, 0, fmt.Errorf("required %s state root entry %q is missing", label, required)
		}
	}

	collected := make([]stateTreeEntry, 0, maxFiles)
	var totalBytes int64
	fileCount := 0
	err = filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symbolic link is prohibited at %q", path)
		}
		isWriterLock := path == filepath.Join(root, spoolLockFilename) || path == filepath.Join(root, startLedgerLockFilename)
		if isWriterLock && !info.Mode().IsRegular() {
			return errors.New("state writer lock must be a regular file")
		}
		owner, group, nlink, securityErr := validateStateSecurity(info, info.IsDir())
		if securityErr != nil {
			return fmt.Errorf("unsafe state entry %q: %w", path, securityErr)
		}
		if stateSecurityMetadataAvailable() && (owner != rootOwner || group != rootGroup) {
			return fmt.Errorf("state entry %q has a different owner", path)
		}
		if info.IsDir() {
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			collected = append(collected, stateTreeEntry{
				relative: label + "/" + filepath.ToSlash(relative), digest: "directory",
				mode: info.Mode(), owner: owner, group: group, nlink: nlink, identity: stateFileIdentity(info),
			})
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("state entry %q is not a regular file", path)
		}
		if isWriterLock && info.Size() != 0 {
			return errors.New("state writer lock file must be empty")
		}
		if fileCount >= maxFiles {
			return errors.New("state tree file limit exceeded")
		}
		fileCount++
		if info.Size() < 0 || info.Size() > maxBytes-totalBytes {
			return errors.New("state tree byte limit exceeded")
		}
		totalBytes += info.Size()
		raw, err := readStableStateFile(path, info, maxBytes)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(raw)
		collected = append(collected, stateTreeEntry{
			relative: label + "/" + filepath.ToSlash(relative), digest: hex.EncodeToString(digest[:]),
			size: info.Size(), mode: info.Mode(), owner: owner, group: group, nlink: nlink, identity: stateFileIdentity(info),
		})
		return nil
	})
	if err != nil {
		return nil, 0, 0, fmt.Errorf("inspect %s state tree: %w", label, err)
	}
	return collected, rootOwner, rootGroup, nil
}

func readStableStateFile(path string, before os.FileInfo, maximum int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open state file %q: %w", path, err)
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) || after.Size() != before.Size() {
		return nil, fmt.Errorf("state file %q identity changed while opening", path)
	}
	if after.Size() > maximum {
		return nil, fmt.Errorf("state file %q exceeds validation bound", path)
	}
	raw := make([]byte, after.Size())
	if _, err := file.ReadAt(raw, 0); err != nil && len(raw) != 0 {
		return nil, fmt.Errorf("read state file %q: %w", path, err)
	}
	return raw, nil
}

func validateLatestStateRelationships(latest startLedgerDisk, segments []spoolMeta) (int, error) {
	byEvidence := make(map[string][]ProbeResult)
	byRun := make(map[string]ProbeResult, len(segments))
	missingRuns := make(map[string]struct{})
	for _, segment := range segments {
		result := segment.result
		if _, duplicate := byRun[result.RunID]; duplicate {
			return 0, fmt.Errorf("duplicate spool result run ID %q", result.RunID)
		}
		byRun[result.RunID] = result
		if result.EvidenceRef != "" {
			byEvidence[result.EvidenceRef] = append(byEvidence[result.EvidenceRef], result)
			if len(byEvidence[result.EvidenceRef]) > 1 {
				return 0, fmt.Errorf("duplicate spool evidence reference %q", result.EvidenceRef)
			}
		}
	}
	for _, entry := range latest.Starts {
		matches := byEvidence[entry.StartID]
		if entry.SettledAt == nil {
			if len(matches) == 1 && (matches[0].ProbeID != entry.ProbeID || matches[0].AttemptedAt.Before(entry.StartedAt)) {
				return 0, fmt.Errorf("in-flight start %q has mismatched crash-window evidence", entry.StartID)
			}
			continue
		}
		result, retained := byRun[entry.ResultRunID]
		if !retained {
			if len(matches) != 0 {
				return 0, fmt.Errorf("settled start %q is referenced by the wrong retained spool result", entry.StartID)
			}
			missingRuns[entry.ResultRunID] = struct{}{}
			continue
		}
		if len(matches) != 1 || matches[0].RunID != result.RunID || result.EvidenceRef != entry.StartID || result.ProbeID != entry.ProbeID || result.AttemptedAt.Before(entry.StartedAt) || !result.CompletedAt.Equal(*entry.SettledAt) {
			return 0, fmt.Errorf("settled start %q does not match its spool result", entry.StartID)
		}
	}
	for _, fact := range latest.RateLimits {
		result, exists := byRun[fact.SourceRunID]
		if !exists {
			missingRuns[fact.SourceRunID] = struct{}{}
			continue
		}
		wantNotBefore := result.CompletedAt.Add(time.Duration(result.Layers.Business.RetryAfterSeconds) * time.Second)
		if result.ProbeID != fact.ProbeID || result.Conclusion != ConclusionRateLimited || result.Layers.Business.RetryAfterSeconds <= 0 || !result.CompletedAt.Equal(fact.ObservedAt) || !wantNotBefore.Equal(fact.NotBefore) {
			return 0, fmt.Errorf("rate-limit fact for probe %q does not match its source result", fact.ProbeID)
		}
	}
	return len(missingRuns), nil
}

func sameStateTree(first, second []stateTreeEntry) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index] != second[index] {
			return false
		}
	}
	return true
}

func digestStateTree(entries []stateTreeEntry) string {
	hash := sha256.New()
	for _, entry := range entries {
		fmt.Fprintf(hash, "%s\x00%d\x00%d\x00%d\x00%d\x00%d\x00%s\x00", entry.relative, entry.size, uint32(entry.mode), entry.owner, entry.group, entry.nlink, entry.digest)
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func digestStateReadPaths(spoolDirectory, ledgerDirectory string) string {
	hash := sha256.Sum256([]byte(filepath.Clean(spoolDirectory) + "\x00" + filepath.Clean(ledgerDirectory)))
	return "sha256:" + hex.EncodeToString(hash[:])
}
