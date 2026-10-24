package authn

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"chengwang/internal/authz"
)

var (
	ErrSnapshotUnavailable = errors.New("credential snapshot unavailable")
	ErrSnapshotStale       = errors.New("credential snapshot reference invalid or stale")
	ErrSnapshotClock       = errors.New("credential snapshot trusted time rejected")
	ErrSnapshotClosed      = errors.New("credential snapshot manager closed")
	ErrSnapshotUnsupported = errors.New("credential snapshot platform unsupported")
)

const snapshotManagerLabel = "authn.SnapshotManager(memory_freshness_only_not_authorization)"
const snapshotRefLabel = "authn.SnapshotRef(memory_bound_not_authorization)"

// SnapshotRef is a process-local observation reference, not an approval,
// credential, RBAC decision or device-execution permit. Its fields cannot be
// supplied by JSON. Same-package malicious code or an arbitrary replacement
// binary remains outside this trusted-code boundary.
type SnapshotRef struct {
	core *snapshotRefCore
}

type snapshotRefCore struct {
	owner      *snapshotManagerCore
	manager    [32]byte
	epoch      [32]byte
	generation uint64
}

func (SnapshotRef) String() string   { return snapshotRefLabel }
func (SnapshotRef) GoString() string { return snapshotRefLabel }
func (SnapshotRef) MarshalJSON() ([]byte, error) {
	return []byte(`{"scope":"MEMORY_AUTHN_SNAPSHOT_REFERENCE_NOT_AUTHORIZATION"}`), nil
}
func (ref *SnapshotRef) UnmarshalJSON([]byte) error {
	if ref != nil {
		*ref = SnapshotRef{}
	}
	return ErrSnapshotStale
}
func (SnapshotRef) Format(state fmt.State, verb rune) {
	_, _ = io.WriteString(state, snapshotRefLabel)
}

// SnapshotManager uses one path fixed by trusted startup code. It is not an
// HTTP path selector. Every authentication and CurrentPrincipal call rereads
// the file; there is no timer cache or fallback to the previous Store.
// A successful call proves only the observed instant. Credential replacement
// and a later external HTTP Do cannot form one atomic transaction.
// An intermediate replacement reverted between two reads is not observed;
// every observed change or read failure retires the previous reference.
type SnapshotManager struct {
	core *snapshotManagerCore
}

type snapshotManagerCore struct {
	mu         sync.Mutex
	path       string
	manager    [32]byte
	epoch      [32]byte
	generation uint64
	digest     [sha256.Size]byte
	store      *Store
	ref        *snapshotRefCore
	lastTime   time.Time
	closed     bool
	read       func(string) (credentialSnapshot, error)
	random     io.Reader
}

func (SnapshotManager) String() string   { return snapshotManagerLabel }
func (SnapshotManager) GoString() string { return snapshotManagerLabel }
func (SnapshotManager) MarshalJSON() ([]byte, error) {
	return []byte(`{"scope":"MEMORY_AUTHN_FRESHNESS_NOT_AUTHORIZATION"}`), nil
}
func (SnapshotManager) Format(state fmt.State, verb rune) {
	_, _ = io.WriteString(state, snapshotManagerLabel)
}

// OpenSnapshotManager samples the supplied trusted time, never time.Now.
// Linux custody is mandatory; unsupported platforms fail closed without
// changing the legacy immutable Store.Open API.
func OpenSnapshotManager(path string, now time.Time) (*SnapshotManager, error) {
	if !snapshotPlatformSupported() {
		return nil, ErrSnapshotUnsupported
	}
	if !snapshotTime(now) {
		return nil, ErrSnapshotClock
	}
	if path == "" || strings.TrimSpace(path) != path || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrSnapshotUnavailable
	}
	core := &snapshotManagerCore{path: path, random: rand.Reader,
		read: func(path string) (credentialSnapshot, error) { return readCredentialSnapshot(path, true, nil) }}
	if _, err := io.ReadFull(core.random, core.manager[:]); err != nil || core.manager == [32]byte{} {
		return nil, ErrSnapshotUnavailable
	}
	if err := core.refresh(now); err != nil {
		return nil, err
	}
	return &SnapshotManager{core: core}, nil
}

func snapshotTime(now time.Time) bool {
	return !now.IsZero() && now.UTC().Year() >= 1 && now.UTC().Year() <= 9999
}

func (core *snapshotManagerCore) invalidate() {
	core.store = nil
	core.ref = nil
	core.digest = [sha256.Size]byte{}
	core.epoch = [32]byte{}
}

// Caller holds core.mu (or owns the not-yet-published constructor instance).
func (core *snapshotManagerCore) refresh(now time.Time) error {
	if core.closed {
		return ErrSnapshotClosed
	}
	if !snapshotTime(now) || (!core.lastTime.IsZero() && now.Before(core.lastTime)) {
		core.invalidate()
		return ErrSnapshotClock
	}
	core.lastTime = now.UTC()
	next, err := core.read(core.path)
	if err != nil || next.store == nil {
		core.invalidate()
		return ErrSnapshotUnavailable
	}
	if core.store == nil || core.digest != next.digest {
		// Clear the previous epoch BEFORE attempting randomness. Failure cannot
		// revive old approval references even if the old bytes later return.
		previous := core.epoch
		core.invalidate()
		if core.generation == ^uint64(0) {
			return ErrSnapshotUnavailable
		}
		core.generation++
		var epoch [32]byte
		if _, err := io.ReadFull(core.random, epoch[:]); err != nil || epoch == [32]byte{} || epoch == previous {
			return ErrSnapshotUnavailable
		}
		core.epoch = epoch
		core.ref = &snapshotRefCore{owner: core, manager: core.manager, epoch: epoch, generation: core.generation}
	}
	core.digest, core.store = next.digest, next.store
	return nil
}

func (manager *SnapshotManager) lock() (*snapshotManagerCore, error) {
	if manager == nil || manager.core == nil {
		return nil, ErrSnapshotUnavailable
	}
	core := manager.core
	core.mu.Lock()
	return core, nil
}

func (manager *SnapshotManager) AuthenticateAuthorizationValues(headers []string, now time.Time) (authz.Principal, SnapshotRef, error) {
	core, err := manager.lock()
	if err != nil {
		return authz.Principal{}, SnapshotRef{}, err
	}
	defer core.mu.Unlock()
	if err := core.refresh(now); err != nil {
		return authz.Principal{}, SnapshotRef{}, err
	}
	principal, err := core.store.AuthenticateAuthorizationValues(headers, now)
	if err != nil {
		return authz.Principal{}, SnapshotRef{}, err
	}
	return principal, SnapshotRef{core: core.ref}, nil
}

func (manager *SnapshotManager) AuthenticateAuthorization(header string, now time.Time) (authz.Principal, SnapshotRef, error) {
	return manager.AuthenticateAuthorizationValues([]string{header}, now)
}

// CurrentPrincipal revalidates activity and returns fresh roles/scope; it does
// NOT authenticate a caller merely because they supplied an id. Only a trusted
// service may use a saved approval principal id with its retained SnapshotRef.
// The caller must separately Evaluate the actual requested RBAC action.
func (manager *SnapshotManager) CurrentPrincipal(ref SnapshotRef, id string, now time.Time) (authz.Principal, error) {
	core, err := manager.lock()
	if err != nil {
		return authz.Principal{}, err
	}
	defer core.mu.Unlock()
	if err := core.refresh(now); err != nil {
		return authz.Principal{}, err
	}
	if ref.core == nil || ref.core != core.ref || ref.core.owner != core || ref.core.generation != core.generation || subtle.ConstantTimeCompare(ref.core.manager[:], core.manager[:]) != 1 || subtle.ConstantTimeCompare(ref.core.epoch[:], core.epoch[:]) != 1 || ref.core.epoch == [32]byte{} {
		return authz.Principal{}, ErrSnapshotStale
	}
	if validateIdentifier("principal.id", id, 128) != nil {
		return authz.Principal{}, ErrSnapshotStale
	}
	for _, identity := range core.store.identities {
		record := identity.record
		if record.Principal.ID != id {
			continue
		}
		if record.Disabled {
			return authz.Principal{}, denied(CodeIdentityDisabled)
		}
		if record.NotBefore != nil && now.Before(*record.NotBefore) {
			return authz.Principal{}, denied(CodeIdentityNotActive)
		}
		if record.ExpiresAt != nil && !now.Before(*record.ExpiresAt) {
			return authz.Principal{}, denied(CodeIdentityExpired)
		}
		return clonePrincipal(record.Principal), nil
	}
	return authz.Principal{}, denied(CodeTokenInvalid)
}

// Close invalidates every reference, including copied manager values which
// share this core. No secret path, credential digest or epoch is exported.
func (manager *SnapshotManager) Close() error {
	core, err := manager.lock()
	if err != nil {
		return err
	}
	defer core.mu.Unlock()
	core.invalidate()
	core.closed = true
	return nil
}
