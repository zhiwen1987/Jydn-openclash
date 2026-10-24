//go:build linux

package mihomodeploy

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const artifactOpenFlags = syscall.O_CLOEXEC | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
type artifactDirectory struct { file *os.File; name string; identity syscall.Stat_t }
type artifactLinuxDisk struct {
	chain []artifactDirectory
	objects, lock *os.File
	objectsIdentity, lockIdentity syscall.Stat_t
	indexIdentity syscall.Stat_t
	indexExists, closed bool
	uid, gid uint32
	// Private syscall seams support explicit disk-fault tests, never API faults.
	syncDirectory func(*os.File) error
}
func artifactStat(f *os.File) (syscall.Stat_t, error) {
	var v syscall.Stat_t
	if syscall.Fstat(int(f.Fd()), &v) != nil { return v, ErrArtifactUnsafe }
	return v, nil
}
func artifactSame(a, b syscall.Stat_t, content bool) bool {
	if a.Dev != b.Dev || a.Ino != b.Ino || a.Mode != b.Mode || a.Uid != b.Uid || a.Gid != b.Gid { return false }
	if a.Mode&syscall.S_IFMT != syscall.S_IFDIR && a.Nlink != b.Nlink { return false }
	return !content || a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}
func (d *artifactLinuxDisk) directory() *os.File { return d.chain[len(d.chain)-1].file }
func artifactOpen(dir *os.File, name string, flags int, mode uint32) (*os.File, error) {
	fd, err := syscall.Openat(int(dir.Fd()), name, flags|artifactOpenFlags, mode)
	if err != nil { return nil, err }; return os.NewFile(uintptr(fd), name), nil
}
func (d *artifactLinuxDisk) fileSafe(v syscall.Stat_t) bool {
	return v.Mode&syscall.S_IFMT == syscall.S_IFREG && v.Mode&07777 == 0600 && v.Uid == d.uid && v.Gid == d.gid && v.Nlink == 1 && v.Size >= 0
}
func (d *artifactLinuxDisk) directorySafe(v syscall.Stat_t, leaf bool, path string) bool {
	if v.Mode&syscall.S_IFMT != syscall.S_IFDIR { return false }
	if leaf { return v.Uid == d.uid && v.Gid == d.gid && v.Mode&07777 == 0700 }
	if path == "/tmp" && v.Uid == 0 && v.Mode&07777 == 01777 { return true }
	return (v.Uid == 0 || v.Uid == d.uid) && v.Mode&0022 == 0 && v.Mode&07000 == 0
}
func openArtifactDisk(path string) (artifactDisk, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" { return nil, ErrArtifactUnsafe }
	d := &artifactLinuxDisk{uid: uint32(os.Geteuid()), gid: uint32(os.Getegid()), syncDirectory: func(f *os.File) error { return f.Sync() }}
	keep := false; defer func() { if !keep { _ = d.close() } }()
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|artifactOpenFlags, 0)
	if err != nil { return nil, ErrArtifactUnsafe }
	root := os.NewFile(uintptr(fd), "/"); st, err := artifactStat(root)
	if err != nil || !d.directorySafe(st, false, "/") { _ = root.Close(); return nil, ErrArtifactUnsafe }
	d.chain = append(d.chain, artifactDirectory{file: root, identity: st})
	current := ""; parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, name := range parts {
		if name == "" || name == "." || name == ".." { return nil, ErrArtifactUnsafe }
		parent := d.directory(); current += "/" + name
		child, err := artifactOpen(parent, name, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
		if errors.Is(err, syscall.ENOENT) && i == len(parts)-1 {
			if syscall.Mkdirat(int(parent.Fd()), name, 0700) != nil || parent.Sync() != nil { return nil, ErrArtifactUnsafe }
			child, err = artifactOpen(parent, name, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
		}
		if err != nil { return nil, ErrArtifactUnsafe }
		v, err := artifactStat(child)
		if err != nil || !d.directorySafe(v, i == len(parts)-1, current) { _ = child.Close(); return nil, ErrArtifactUnsafe }
		d.chain = append(d.chain, artifactDirectory{child, name, v})
	}
	var fs syscall.Statfs_t
	if syscall.Fstatfs(int(d.directory().Fd()), &fs) != nil || !(fs.Type == 0xef53 || fs.Type == 0x58465342 || fs.Type == 0x01021994) { return nil, ErrArtifactUnsupported }
	lock, err := artifactOpen(d.directory(), "writer.lock", syscall.O_RDWR|syscall.O_CREAT, 0600)
	if err != nil { return nil, ErrArtifactUnsafe }; d.lock = lock
	if d.lockIdentity, err = artifactStat(lock); err != nil || !d.fileSafe(d.lockIdentity) || d.lockIdentity.Size != 0 { return nil, ErrArtifactUnsafe }
	if syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil { return nil, ErrArtifactUnsafe }
	if lock.Sync() != nil || d.directory().Sync() != nil { return nil, ErrArtifactUnsafe }
	objects, err := artifactOpen(d.directory(), "objects", syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if errors.Is(err, syscall.ENOENT) {
		if syscall.Mkdirat(int(d.directory().Fd()), "objects", 0700) != nil || d.directory().Sync() != nil { return nil, ErrArtifactUnsafe }
		objects, err = artifactOpen(d.directory(), "objects", syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	}
	if err != nil { return nil, ErrArtifactUnsafe }; d.objects = objects
	if d.objectsIdentity, err = artifactStat(objects); err != nil || !d.directorySafe(d.objectsIdentity, true, "") { return nil, ErrArtifactUnsafe }
	index, err := artifactOpen(d.directory(), "index.json", syscall.O_RDONLY, 0)
	if err == nil {
		d.indexIdentity, err = artifactStat(index); _ = index.Close()
		if err != nil || !d.fileSafe(d.indexIdentity) { return nil, ErrArtifactUnsafe }; d.indexExists = true
	} else if !errors.Is(err, syscall.ENOENT) { return nil, ErrArtifactUnsafe }
	// The initial empty index is durable before any Put. Objects without that
	// index cannot be a legitimate new library; never reset references or infer
	// a new head from orphan files after the index was lost.
	if !d.indexExists {
		listing, err := artifactOpen(d.objects, ".", syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
		if err != nil { return nil, ErrArtifactUnsafe }
		entries, readErr := listing.ReadDir(1); closeErr := listing.Close()
		if len(entries) != 0 || (readErr != nil && !errors.Is(readErr, io.EOF)) || closeErr != nil { return nil, ErrArtifactUnsafe }
	}
	if err := d.scan(d.directory(), false, true); err != nil { return nil, err }
	if err := d.scan(d.objects, true, true); err != nil { return nil, err }
	if err := d.verify(); err != nil { return nil, err }
	keep = true; return d, nil
}
func (d *artifactLinuxDisk) named(dir *os.File, name string, expected syscall.Stat_t, content bool) error {
	f, err := artifactOpen(dir, name, syscall.O_RDONLY, 0)
	if err != nil { return ErrArtifactUnsafe }; defer f.Close()
	v, err := artifactStat(f)
	if err != nil || !artifactSame(expected, v, content) { return ErrArtifactUnsafe }; return nil
}
func (d *artifactLinuxDisk) verify() error {
	if d.closed || len(d.chain) == 0 || d.lock == nil || d.objects == nil { return ErrArtifactUnsafe }
	for i, c := range d.chain {
		v, err := artifactStat(c.file)
		if err != nil || !artifactSame(c.identity, v, false) { return ErrArtifactUnsafe }
		if i > 0 && d.named(d.chain[i-1].file, c.name, v, false) != nil { return ErrArtifactUnsafe }
	}
	if d.named(d.directory(), "writer.lock", d.lockIdentity, true) != nil || d.named(d.directory(), "objects", d.objectsIdentity, false) != nil { return ErrArtifactUnsafe }
	if d.indexExists {
		if d.named(d.directory(), "index.json", d.indexIdentity, true) != nil { return ErrArtifactUnsafe }
	} else {
		f, err := artifactOpen(d.directory(), "index.json", syscall.O_RDONLY, 0)
		if err == nil { _ = f.Close(); return ErrArtifactUnsafe }; if !errors.Is(err, syscall.ENOENT) { return ErrArtifactUnsafe }
	}
	if d.scan(d.directory(), false, false) != nil || d.scan(d.objects, true, false) != nil { return ErrArtifactUnsafe }
	return nil
}
func artifactTemp(name string) bool {
	if !strings.HasPrefix(name, ".tmp-") || len(name) != 37 { return false }
	value, err := hex.DecodeString(name[5:]); return err == nil && hex.EncodeToString(value) == name[5:]
}
// Orphan immutable objects are retained within quota. Only exact private temp
// names are removed on reopen; referenced/malformed objects are never "fixed".
func (d *artifactLinuxDisk) scan(dir *os.File, objects, recover bool) error {
	f, err := artifactOpen(dir, ".", syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil { return ErrArtifactUnsafe }; defer f.Close()
	count := 0; var total int64; removed := false
	for {
		entries, readErr := f.ReadDir(32)
		for _, entry := range entries {
			count++; if (objects && count > maxArtifactObjects) || count > maxArtifactObjects+3 { return ErrArtifactLimit }
			name := entry.Name()
			if !objects && (name == "writer.lock" || name == "objects" || name == "index.json") { continue }
			temporary := artifactTemp(name)
			if !temporary && (!objects || !artifactDigest.MatchString(name)) { return ErrArtifactUnsafe }
			if temporary && !recover { return ErrArtifactUnsafe }
			item, err := artifactOpen(dir, name, syscall.O_RDONLY, 0)
			if err != nil { return ErrArtifactUnsafe }
			info, statErr := artifactStat(item); closeErr := item.Close()
			if statErr != nil || closeErr != nil || !d.fileSafe(info) || info.Size > maxSourceSpecBytes || d.named(dir, name, info, true) != nil { return ErrArtifactUnsafe }
			total += info.Size; if total > maxArtifactAggregateBytes { return ErrArtifactLimit }
			if temporary {
				if syscall.Unlinkat(int(dir.Fd()), name) != nil { return ErrArtifactUnsafe }; removed = true
			} else if recover {
				// Full orphan hashes are checked once on open. Every selected object
				// is independently hashed again by the core on read; routine custody
				// checks do not reread the entire 64MiB library for every reference.
				value, err := d.readNamed(dir, name, maxSourceSpecBytes, false)
				if err != nil || labConfigHash(value) != name { return ErrArtifactUnsafe }
			}
		}
		if errors.Is(readErr, io.EOF) { break }; if readErr != nil { return ErrArtifactUnsafe }
	}
	if removed && dir.Sync() != nil { return ErrArtifactUnsafe }; return nil
}
func (d *artifactLinuxDisk) readNamed(dir *os.File, name string, limit int, empty bool) ([]byte, error) {
	f, err := artifactOpen(dir, name, syscall.O_RDONLY, 0)
	if err != nil { return nil, err }; defer f.Close()
	before, err := artifactStat(f)
	if err != nil || !d.fileSafe(before) || before.Size > int64(limit) || (!empty && before.Size == 0) { return nil, ErrArtifactUnsafe }
	raw, err := io.ReadAll(io.LimitReader(f, int64(limit)+1)); after, statErr := artifactStat(f)
	if err != nil || statErr != nil || !artifactSame(before, after, true) || int64(len(raw)) != before.Size || d.named(dir, name, after, true) != nil { return nil, ErrArtifactUnsafe }
	return raw, nil
}
func (d *artifactLinuxDisk) readIndex() ([]byte, bool, error) {
	if d.verify() != nil { return nil, false, ErrArtifactUnsafe }
	if !d.indexExists { return nil, false, nil }
	raw, err := d.readNamed(d.directory(), "index.json", maxArtifactIndexBytes, false); return raw, true, err
}
func (d *artifactLinuxDisk) readObject(id string, limit int) ([]byte, error) {
	if !artifactDigest.MatchString(id) || d.verify() != nil { return nil, ErrArtifactUnsafe }
	return d.readNamed(d.objects, id, limit, false)
}
func (d *artifactLinuxDisk) replace(dir *os.File, name string, raw []byte, replacingIndex bool) (bool, error) {
	if d.verify() != nil { return false, ErrArtifactUnsafe }
	var nonce [16]byte; if _, err := rand.Read(nonce[:]); err != nil { return false, ErrArtifactUnsafe }
	temp := ".tmp-" + hex.EncodeToString(nonce[:])
	f, err := artifactOpen(dir, temp, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL, 0600)
	if err != nil { return false, ErrArtifactUnsafe }
	renamed := false
	defer func() { _ = f.Close(); if !renamed { _ = syscall.Unlinkat(int(dir.Fd()), temp) } }()
	if st, err := artifactStat(f); err != nil || !d.fileSafe(st) { return false, ErrArtifactUnsafe }
	if _, err := io.Copy(f, bytes.NewReader(raw)); err != nil || f.Sync() != nil { return false, ErrArtifactUnsafe }
	written, err := artifactStat(f)
	if err != nil || !d.fileSafe(written) || written.Size != int64(len(raw)) || d.named(dir, temp, written, true) != nil { return false, ErrArtifactUnsafe }
	// Exclusive process lock and private owned directory serialize all writers.
	// Existing immutable names are never replaced; an external same-UID malicious
	// writer is outside this store's owner trust boundary, not defeated by SHA.
	if !replacingIndex {
		existing, err := artifactOpen(dir, name, syscall.O_RDONLY, 0)
		if err == nil { _ = existing.Close(); return false, ErrArtifactUnsafe }
		if !errors.Is(err, syscall.ENOENT) { return false, ErrArtifactUnsafe }
	} else if d.indexExists && d.named(d.directory(), "index.json", d.indexIdentity, true) != nil { return false, ErrArtifactUnsafe }
	for i, c := range d.chain {
		v, err := artifactStat(c.file)
		if err != nil || !artifactSame(c.identity, v, false) || (i > 0 && d.named(d.chain[i-1].file, c.name, v, false) != nil) { return false, ErrArtifactUnsafe }
	}
	if d.named(d.directory(), "writer.lock", d.lockIdentity, true) != nil || d.named(d.directory(), "objects", d.objectsIdentity, false) != nil { return false, ErrArtifactUnsafe }
	if syscall.Renameat(int(dir.Fd()), temp, int(dir.Fd()), name) != nil { return false, ErrArtifactUnsafe }
	renamed = true
	if d.syncDirectory(dir) != nil { return true, ErrArtifactCommitUnknown }
	if replacingIndex {
		st, err := artifactStat(f)
		if err != nil { return true, ErrArtifactCommitUnknown }; d.indexIdentity = st; d.indexExists = true
	}
	if d.verify() != nil { return true, ErrArtifactCommitUnknown }
	return false, nil
}
func (d *artifactLinuxDisk) putObject(raw []byte) (bool, error) {
	if len(raw) == 0 || len(raw) > maxSourceSpecBytes || d.verify() != nil { return false, ErrArtifactUnsafe }
	id := labConfigHash(raw)
	existing, err := d.readNamed(d.objects, id, maxSourceSpecBytes, false)
	if err == nil { if !bytes.Equal(existing, raw) { return false, ErrArtifactUnsafe }; return false, nil }
	if !errors.Is(err, syscall.ENOENT) { return false, ErrArtifactUnsafe }
	// Account existing immutable data before admitting one additional object.
	entries, err := artifactOpen(d.objects, ".", syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil { return false, ErrArtifactUnsafe }; defer entries.Close()
	count := 0; total := int64(len(raw))
	for {
		batch, err := entries.ReadDir(32)
		for _, e := range batch {
			// DirEntry.Info resolves os.NewFile's display name (".") against
			// the working directory. Quotas must instead stay bound to objects.
			object, openErr := artifactOpen(d.objects, e.Name(), syscall.O_RDONLY, 0)
			if openErr != nil { return false, ErrArtifactUnsafe }
			info, statErr := artifactStat(object)
			closeErr := object.Close()
			if statErr != nil || closeErr != nil || !d.fileSafe(info) || info.Size > maxSourceSpecBytes ||
				d.named(d.objects, e.Name(), info, true) != nil { return false, ErrArtifactUnsafe }
			count++; total += info.Size
			if count >= maxArtifactObjects || total > maxArtifactAggregateBytes { return false, ErrArtifactLimit }
		}
		if errors.Is(err, io.EOF) { break }; if err != nil { return false, ErrArtifactUnsafe }
	}
	return d.replace(d.objects, id, raw, false)
}
func (d *artifactLinuxDisk) writeIndex(raw []byte) (bool, error) {
	if len(raw) == 0 || len(raw) > maxArtifactIndexBytes { return false, ErrArtifactLimit }
	return d.replace(d.directory(), "index.json", raw, true)
}
func (d *artifactLinuxDisk) close() error {
	if d.closed { return nil }; d.closed = true; failed := false
	if d.lock != nil { if syscall.Flock(int(d.lock.Fd()), syscall.LOCK_UN) != nil { failed = true }; if d.lock.Close() != nil { failed = true } }
	if d.objects != nil && d.objects.Close() != nil { failed = true }
	for i := len(d.chain)-1; i >= 0; i-- { if d.chain[i].file.Close() != nil { failed = true } }
	if failed { return ErrArtifactUnsafe }; return nil
}
