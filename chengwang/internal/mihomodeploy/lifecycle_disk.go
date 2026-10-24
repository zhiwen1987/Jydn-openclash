package mihomodeploy

import "errors"

// This backend records structural laboratory state. It never grants authority,
// bootstraps a running head, returns a dispatch handle, or contacts a controller.
type lifecycleCommitState uint8

const (
	lifecycleNotCommitted lifecycleCommitState = iota
	lifecycleCommitted
	lifecycleUnknown
)

const maxLifecycleControlBytes = 2 << 20
const lifecycleRootPath = "/var/lib/chengwang-mihomo-lab-lifecycle"
const lifecycleGlobalLockPath = "/run/chengwang-mihomo-lab-writer.lock"

var (
	errLifecycleUnsafe = errors.New("Mihomo laboratory lifecycle state rejected")
	errLifecycleLocked = errors.New("Mihomo laboratory lifecycle writer unavailable")
	errLifecycleCommitUnknown = errors.New("Mihomo laboratory lifecycle commit uncertain")
	errLifecyclePoisoned = errors.New("Mihomo laboratory lifecycle store is fail-closed")
	errLifecycleUnsupported = errors.New("Mihomo laboratory lifecycle durability unsupported")
)

// CAS belongs to the mutex-protected portable store while this disk retains
// both host-wide and directory writer locks. Missing bytes are not bootstrap
// permission. COMMITTED requires an actual safe reopen and exact byte readback.
type lifecycleDisk interface {
	verify() error
	readControl() ([]byte, bool, error)
	replaceControl([]byte) (lifecycleCommitState, error)
	close() error
}
