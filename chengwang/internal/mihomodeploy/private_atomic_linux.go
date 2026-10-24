//go:build linux

package mihomodeploy

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"syscall"
)

// One private writer serves immutable artifact objects/index and opaque WAL.
// Callers retain their own locks, path policy, validation and error classes.
type privateAtomicKind uint8
const (
	privateAtomicArtifact privateAtomicKind = iota + 1
	privateAtomicLifecycle
)
var errPrivateAtomicPolicy = errors.New("private atomic writer policy rejected")
type privateAtomicPolicy struct {
	kind privateAtomicKind
	unsafe, unknown error
	verify func() error
	safe func(syscall.Stat_t) bool
	named func(*os.File, string, syscall.Stat_t) error
	beforeRename func(string) error
	afterRename func(*os.File) error
	syncFile func(*os.File) error
	closeFile func(*os.File) error
	rename func(*os.File, string, string) error
	syncDirectory func(*os.File) error
}

// uncertain is true only once rename succeeded. It never asserts application
// authorization or revision CAS. Lifecycle closes before rename; the original
// artifact path deliberately retains its open-fstat-after-rename semantics.
func privateAtomicReplace(dir *os.File, name string, raw []byte, p privateAtomicPolicy) (uncertain bool, err error) {
	if dir == nil || (name != "index.json" && name != "control.json" && !artifactDigest.MatchString(name)) ||
		(p.kind != privateAtomicArtifact && p.kind != privateAtomicLifecycle) || p.unsafe == nil || p.unknown == nil ||
		p.verify == nil || p.safe == nil || p.named == nil || p.beforeRename == nil || p.afterRename == nil ||
		p.syncFile == nil || p.closeFile == nil || p.rename == nil || p.syncDirectory == nil {
		return false, errPrivateAtomicPolicy
	}
	if p.verify() != nil { return false, p.unsafe }
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil { return false, p.unsafe }
	temp := ".tmp-" + hex.EncodeToString(nonce[:])
	f, err := artifactOpen(dir, temp, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL, 0600)
	if err != nil { return false, p.unsafe }
	renamed := false
	defer func() { _ = f.Close(); if !renamed { _ = syscall.Unlinkat(int(dir.Fd()), temp) } }()
	if st, err := artifactStat(f); err != nil || !p.safe(st) { return false, p.unsafe }
	if _, err := io.Copy(f, bytes.NewReader(raw)); err != nil || p.syncFile(f) != nil { return false, p.unsafe }
	written, err := artifactStat(f)
	if err != nil || !p.safe(written) || written.Size != int64(len(raw)) || p.named(dir, temp, written) != nil { return false, p.unsafe }
	if p.kind == privateAtomicLifecycle && p.closeFile(f) != nil { return false, p.unsafe }
	if p.beforeRename(temp) != nil { return false, p.unsafe }
	if p.kind == privateAtomicLifecycle && p.named(dir, temp, written) != nil { return false, p.unsafe }
	if p.rename(dir, temp, name) != nil { return false, p.unsafe }
	renamed = true
	if p.syncDirectory(dir) != nil { return true, p.unknown }
	if p.afterRename(f) != nil { return true, p.unknown }
	return false, nil
}
