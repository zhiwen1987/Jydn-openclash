//go:build linux

package probe

import (
	"context"
	"errors"
	"io"
	"math"
	"os"
	"sort"
	"syscall"
)

const secureDirectoryFlags = syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK | syscall.O_CLOEXEC
const secureFileFlags = syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK | syscall.O_CLOEXEC

type secureDirectoryPolicy uint8

const (
	secureAncestor secureDirectoryPolicy = iota
	secureStateDirectory
	secureCatalogDirectory
)

type secureDirectory struct {
	file   *os.File
	name   string
	parent *secureDirectory
	before syscall.Stat_t
	policy secureDirectoryPolicy
}

type secureDirectoryChain struct {
	dirs  []*secureDirectory
	owner SecureFileOwner
}

type secureRegular struct {
	file    *os.File
	parent  *secureDirectory
	name    string
	before  syscall.Stat_t
	owner   SecureFileOwner
	catalog bool
}

func secureOSError(ctx context.Context, err error) error {
	if canceled := secureContext(ctx); canceled != nil {
		return canceled
	}
	if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.ENOTDIR) {
		return ErrSecureUnsafe
	}
	if errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.EAGAIN) {
		return ErrSecureChanged
	}
	return ErrSecureIO
}

func secureStat(file *os.File) (syscall.Stat_t, error) {
	var value syscall.Stat_t
	if syscall.Fstat(int(file.Fd()), &value) != nil {
		return value, ErrSecureIO
	}
	return value, nil
}

func secureFilesystem(file *os.File, ancestor bool) error {
	var value syscall.Statfs_t
	if syscall.Fstatfs(int(file.Fd()), &value) != nil {
		return ErrSecureIO
	}
	// Overlay is allowed only for trusted traversal ancestors (e.g. an image's
	// root). Actual state/catalog directories and files must be native local FS.
	if value.Type == 0xef53 || value.Type == 0x58465342 || value.Type == 0x01021994 || ancestor && value.Type == 0x794c7630 {
		return nil
	}
	return ErrSecureUnsupported
}

func secureSame(a, b syscall.Stat_t, full bool) bool {
	if a.Dev != b.Dev || a.Ino != b.Ino || a.Mode != b.Mode || a.Uid != b.Uid || a.Gid != b.Gid {
		return false
	}
	return !full || a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

func secureDirectoryMetadata(value syscall.Stat_t, owner SecureFileOwner, policy secureDirectoryPolicy) error {
	if value.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return ErrSecureUnsafe
	}
	mode := value.Mode & 0o7777
	switch policy {
	case secureStateDirectory:
		if value.Uid != owner.UID || value.Gid != owner.GID || mode != 0o700 {
			return ErrSecureUnsafe
		}
	case secureCatalogDirectory:
		if !(value.Uid == owner.UID && value.Gid == owner.GID && mode == 0o700 || value.Uid == 0 && value.Gid == owner.GID && mode == 0o750) {
			return ErrSecureUnsafe
		}
	default:
		if value.Uid != 0 && value.Uid != owner.UID || mode&0o7000 != 0 || mode&0o022 != 0 {
			// A root-owned sticky /tmp-style ancestor is a deliberate exception;
			// the actual state/catalog leaf still requires its stricter policy.
			if value.Uid != 0 || mode != 0o1777 {
				return ErrSecureUnsafe
			}
		}
	}
	return nil
}

func (chain *secureDirectoryChain) close() {
	for i := len(chain.dirs) - 1; i >= 0; i-- {
		_ = chain.dirs[i].file.Close()
	}
}

func (chain *secureDirectoryChain) append(ctx context.Context, name string, policy secureDirectoryPolicy) (*secureDirectory, error) {
	if err := secureContext(ctx); err != nil {
		return nil, err
	}
	var parent *secureDirectory
	var fd int
	var err error
	if len(chain.dirs) == 0 {
		fd, err = syscall.Open("/", secureDirectoryFlags, 0)
	} else {
		parent = chain.dirs[len(chain.dirs)-1]
		fd, err = syscall.Openat(int(parent.file.Fd()), name, secureDirectoryFlags, 0)
	}
	if err != nil {
		return nil, secureOSError(ctx, err)
	}
	file := os.NewFile(uintptr(fd), "secure-probe-directory")
	value, err := secureStat(file)
	if err == nil {
		err = secureDirectoryMetadata(value, chain.owner, policy)
	}
	if err == nil {
		err = secureFilesystem(file, policy == secureAncestor)
	}
	if err == nil {
		err = secureContext(ctx)
	}
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	directory := &secureDirectory{file: file, parent: parent, name: name, before: value, policy: policy}
	chain.dirs = append(chain.dirs, directory)
	return directory, nil
}

func openSecureDirectories(ctx context.Context, parts []string, owner SecureFileOwner, leaf secureDirectoryPolicy) (*secureDirectoryChain, error) {
	chain := &secureDirectoryChain{owner: owner}
	if _, err := chain.append(ctx, "", secureAncestor); err != nil {
		return nil, err
	}
	for index, part := range parts {
		policy := secureAncestor
		if index == len(parts)-1 {
			policy = leaf
		}
		if _, err := chain.append(ctx, part, policy); err != nil {
			chain.close()
			return nil, err
		}
	}
	return chain, nil
}

func (chain *secureDirectoryChain) verify(ctx context.Context) error {
	for _, held := range chain.dirs {
		if err := secureContext(ctx); err != nil {
			return err
		}
		current, err := secureStat(held.file)
		if err != nil {
			return err
		}
		if !secureSame(held.before, current, held.policy != secureAncestor) {
			return ErrSecureChanged
		}
		var fd int
		if held.parent == nil {
			fd, err = syscall.Open("/", secureDirectoryFlags, 0)
		} else {
			fd, err = syscall.Openat(int(held.parent.file.Fd()), held.name, secureDirectoryFlags, 0)
		}
		if err != nil {
			return secureOSError(ctx, err)
		}
		named := os.NewFile(uintptr(fd), "secure-probe-directory-check")
		value, statErr := secureStat(named)
		fsErr := secureFilesystem(named, held.policy == secureAncestor)
		_ = named.Close()
		if statErr != nil {
			return statErr
		}
		if fsErr != nil {
			return fsErr
		}
		if !secureSame(held.before, value, held.policy != secureAncestor) {
			return ErrSecureChanged
		}
	}
	return secureContext(ctx)
}

func secureRegularMetadata(value syscall.Stat_t, owner SecureFileOwner, catalog bool) error {
	if value.Mode&syscall.S_IFMT != syscall.S_IFREG || value.Nlink != 1 || value.Size < 0 {
		return ErrSecureUnsafe
	}
	mode := value.Mode & 0o7777
	if value.Uid == owner.UID && value.Gid == owner.GID && mode == 0o600 {
		return nil
	}
	if catalog && value.Uid == 0 && value.Gid == owner.GID && mode == 0o640 {
		return nil
	}
	return ErrSecureUnsafe
}

func openSecureRegular(ctx context.Context, parent *secureDirectory, name string, owner SecureFileOwner, catalog bool) (*secureRegular, error) {
	if err := secureContext(ctx); err != nil {
		return nil, err
	}
	fd, err := syscall.Openat(int(parent.file.Fd()), name, secureFileFlags, 0)
	if err != nil {
		return nil, secureOSError(ctx, err)
	}
	file := os.NewFile(uintptr(fd), "secure-probe-file")
	value, err := secureStat(file)
	if err == nil {
		err = secureRegularMetadata(value, owner, catalog)
	}
	if err == nil {
		err = secureFilesystem(file, false)
	}
	if err == nil && value.Dev != parent.before.Dev {
		err = ErrSecureUnsafe
	}
	if err == nil {
		err = secureContext(ctx)
	}
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	return &secureRegular{file: file, parent: parent, name: name, before: value, owner: owner, catalog: catalog}, nil
}

func (held *secureRegular) verify(ctx context.Context) error {
	if err := secureContext(ctx); err != nil {
		return err
	}
	current, err := secureStat(held.file)
	if err != nil {
		return err
	}
	if !secureSame(held.before, current, true) {
		return ErrSecureChanged
	}
	named, err := openSecureRegular(ctx, held.parent, held.name, held.owner, held.catalog)
	if err != nil {
		return err
	}
	defer named.file.Close()
	if !secureSame(held.before, named.before, true) {
		return ErrSecureChanged
	}
	return secureContext(ctx)
}

func (held *secureRegular) read(ctx context.Context, limit int64) ([]byte, error) {
	if held.before.Size <= 0 || held.before.Size > limit {
		return nil, ErrSecureLimit
	}
	raw := make([]byte, 0, int(held.before.Size))
	var buffer [16 << 10]byte
	for int64(len(raw)) <= limit {
		if err := secureContext(ctx); err != nil {
			return nil, err
		}
		remaining := limit + 1 - int64(len(raw))
		size := len(buffer)
		if remaining < int64(size) {
			size = int(remaining)
		}
		n, err := syscall.Read(int(held.file.Fd()), buffer[:size])
		if n > 0 {
			raw = append(raw, buffer[:n]...)
		}
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			return nil, secureOSError(ctx, err)
		}
		if n == 0 {
			break
		}
	}
	if int64(len(raw)) != held.before.Size {
		return nil, ErrSecureChanged
	}
	if err := held.verify(ctx); err != nil {
		return nil, err
	}
	return raw, nil
}

// ReadCatalogSecure reads one immutable private catalog without creating or
// repairing files. Its parent must be owner:group 0700 or root:group 0750.
// Cancellation is cooperative between bounded syscalls; this is not a promise
// to interrupt a wedged kernel/local disk. No background I/O goroutine is used.
func ReadCatalogSecure(ctx context.Context, path string, owner SecureFileOwner) (Catalog, error) {
	if err := secureContext(ctx); err != nil {
		return Catalog{}, err
	}
	parts, err := securePathParts(path)
	if err != nil || len(parts) < 2 {
		return Catalog{}, ErrSecureInvalid
	}
	chain, err := openSecureDirectories(ctx, parts[:len(parts)-1], owner, secureCatalogDirectory)
	if err != nil {
		return Catalog{}, err
	}
	defer chain.close()
	held, err := openSecureRegular(ctx, chain.dirs[len(chain.dirs)-1], parts[len(parts)-1], owner, true)
	if err != nil {
		return Catalog{}, err
	}
	defer held.file.Close()
	raw, err := held.read(ctx, MaxCatalogBytes)
	if err != nil {
		return Catalog{}, err
	}
	catalog, err := ParseCatalogBytes(raw)
	if err != nil {
		return Catalog{}, ErrSecureInvalid
	}
	if err := held.verify(ctx); err != nil {
		return Catalog{}, err
	}
	if err := chain.verify(ctx); err != nil {
		return Catalog{}, err
	}
	return catalog, nil
}

// ReadStoreSecure observes immutable local spool segments through held parent
// FDs. It rejects structural changes for the entire round, never acquires the
// writer lock and never repairs data. Cooperating atomic appends can make one
// round fail with ErrSecureChanged; the caller may poll again, not retry here.
// Uncooperative root/mount changes or kernel/storage stalls are not a promised
// hard-cancellation boundary. A returned view has no post-return mutation lease.
func ReadStoreSecure(ctx context.Context, directory string, options SecureReadOptions) (SecureReadReport, error) {
	options, binding, err := secureOptions(ctx, options)
	if err != nil {
		return SecureReadReport{}, err
	}
	parts, err := securePathParts(directory)
	if err != nil {
		return SecureReadReport{}, err
	}
	owner := SecureFileOwner{UID: options.OwnerUID, GID: options.OwnerGID}
	chain, err := openSecureDirectories(ctx, parts, owner, secureStateDirectory)
	if err != nil {
		return SecureReadReport{}, err
	}
	defer chain.close()
	segments, err := chain.append(ctx, spoolSegmentsDirectory, secureStateDirectory)
	if err != nil {
		return SecureReadReport{}, err
	}
	report := SecureReadReport{}
	fail := func(err error) (SecureReadReport, error) {
		return SecureReadReport{ReadReport: ReadReport{TotalEntries: report.ScannedEntries, TotalBytes: report.TotalBytes}, ScannedEntries: report.ScannedEntries}, err
	}
	entries := make([]os.DirEntry, 0, min(options.MaxEntries+1, DefaultSpoolMaxEntries+1))
	for {
		if err := secureContext(ctx); err != nil {
			return fail(err)
		}
		batch, readErr := segments.file.ReadDir(128)
		entries = append(entries, batch...)
		report.ScannedEntries += len(batch)
		if err := secureContext(ctx); err != nil {
			return fail(err)
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return fail(ErrSecureIO)
		}
		if report.ScannedEntries > options.MaxEntries || report.ScannedEntries > DefaultSpoolMaxEntries {
			return fail(ErrSecureLimit)
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if len(batch) == 0 {
			return fail(ErrSecureIO)
		}
	}
	report.TotalEntries = report.ScannedEntries
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	type observedFile struct {
		name string
		stat syscall.Stat_t
	}
	observed := make([]observedFile, 0, len(entries))
	valid := make([]spoolMeta, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))
	reject := func(reason string) {
		report.Rejected++
		report.Issues = append(report.Issues, ReadIssue{Reason: reason})
		if report.Issue == "" {
			report.Issue = reason
		}
	}
	for _, entry := range entries {
		if err := secureContext(ctx); err != nil {
			return fail(err)
		}
		held, err := openSecureRegular(ctx, segments, entry.Name(), owner, false)
		if err != nil {
			return fail(err)
		}
		if held.before.Size > math.MaxInt64-report.TotalBytes {
			_ = held.file.Close()
			return fail(ErrSecureLimit)
		}
		report.TotalBytes += held.before.Size
		if report.TotalBytes > options.MaxBytes {
			_ = held.file.Close()
			return fail(ErrSecureLimit)
		}
		observed = append(observed, observedFile{name: entry.Name(), stat: held.before})
		raw, readErr := held.read(ctx, MaximumSpoolSegmentBytes)
		closeErr := held.file.Close()
		if readErr != nil {
			return fail(readErr)
		}
		if closeErr != nil {
			return fail(ErrSecureIO)
		}
		segment, reason := decodeSecureSegment(raw, binding, options.Now, options.MaxFutureSkew)
		if err := secureContext(ctx); err != nil {
			return fail(err)
		}
		if reason != "" {
			reject(reason)
			continue
		}
		if entry.Name() != spoolSegmentFileName(segment) {
			reject("filename_mismatch")
			continue
		}
		if _, duplicate := seen[segment.Result.RunID]; duplicate {
			reject("duplicate_run_id")
			continue
		}
		seen[segment.Result.RunID] = struct{}{}
		report.ValidTotal++
		expired := !segment.Result.ExpiresAt.After(options.Now)
		if expired {
			report.ExpiredTotal++
		}
		if !expired || options.IncludeExpired {
			valid = append(valid, spoolMeta{name: entry.Name(), size: int64(len(raw)), result: segment.Result})
		}
	}
	// Reopen each observed name through the same held segments FD. This bounds
	// descriptor usage independently of the 4096-entry budget and rechecks all
	// original metadata before publishing; it is not an atomic hostile-writer lease.
	for _, before := range observed {
		held, err := openSecureRegular(ctx, segments, before.name, owner, false)
		if err != nil {
			return fail(err)
		}
		same := secureSame(before.stat, held.before, true)
		_ = held.file.Close()
		if !same {
			return fail(ErrSecureChanged)
		}
	}
	if err := chain.verify(ctx); err != nil {
		return fail(err)
	}
	sort.Slice(valid, func(i, j int) bool {
		if valid[i].result.CompletedAt.Equal(valid[j].result.CompletedAt) {
			return valid[i].name < valid[j].name
		}
		return valid[i].result.CompletedAt.Before(valid[j].result.CompletedAt)
	})
	report.EligibleTotal = len(valid)
	start := max(0, len(valid)-options.Limit)
	report.Results = make([]ProbeResult, 0, len(valid)-start)
	for _, item := range valid[start:] {
		report.Results = append(report.Results, item.result)
	}
	report.Returned = len(report.Results)
	report.Truncated = report.EligibleTotal > report.Returned
	report.Healthy = report.Rejected == 0
	if err := secureContext(ctx); err != nil {
		return fail(err)
	}
	return report, nil
}
