// Package restorelease owns the process-bound lifecycle locks used by the
// candidate restore path. A Lease is an in-memory capability: persisted
// journal state is not proof that a lease survived a process restart.
package restorelease

import (
	"errors"
	"sync"
)

var (
	ErrBusy              = errors.New("restore lifecycle lease is busy")
	ErrUnsafePath        = errors.New("restore lifecycle path is unsafe")
	ErrUnsupported       = errors.New("restore lifecycle lease is unsupported")
	ErrClosed            = errors.New("restore lifecycle lease is closed")
	ErrPoisoned          = errors.New("restore lifecycle lease is poisoned")
	ErrCandidateMismatch = errors.New("restore lifecycle candidate does not match")
)

type ObjectIdentity struct {
	Device  uint64
	Inode   uint64
	MountID uint64
}

type Identity struct {
	CandidateRoot string
	GlobalDir     ObjectIdentity
	GlobalLock    ObjectIdentity
	CandidateDir  ObjectIdentity
	CandidateLock ObjectIdentity
}

type Lease struct {
	mu       sync.Mutex
	platform *platformLease
	identity Identity
	closed   bool
	poisoned bool
}

// Acquire obtains the production lifecycle locks. Only dedicated candidate
// roots are accepted; callers cannot supply alternate lock paths.
func Acquire(candidateRoot string) (*Lease, error) {
	platform, identity, err := acquirePlatform(candidateRoot)
	if err != nil {
		return nil, err
	}
	return &Lease{platform: platform, identity: identity}, nil
}

// Verify proves that this process still holds the same path-bound file
// objects. The first failed verification permanently poisons the Lease.
func (l *Lease) Verify() error {
	if l == nil {
		return ErrClosed
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.platform == nil {
		return ErrClosed
	}
	if l.poisoned {
		return ErrPoisoned
	}
	if err := l.platform.verify(); err != nil {
		l.poisoned = true
		return errors.Join(ErrPoisoned, err)
	}
	return nil
}

func (l *Lease) Identity() Identity {
	if l == nil {
		return Identity{}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.identity
}

func (l *Lease) CandidateRoot() string {
	return l.Identity().CandidateRoot
}

// Close releases candidate then global lock. It is deliberately idempotent.
func (l *Lease) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	if l.platform == nil {
		return nil
	}
	err := l.platform.close()
	l.platform = nil
	return err
}
