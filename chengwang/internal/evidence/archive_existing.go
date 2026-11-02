package evidence

import "errors"

var (
	// ErrArchiveExistingUnsafe is the fixed, redacted existing-only failure.
	ErrArchiveExistingUnsafe = errors.New("evidence existing snapshot is unsafe")
	// ErrArchiveExistingUnsupported is returned outside the reviewed Linux path.
	ErrArchiveExistingUnsupported = errors.New("evidence existing snapshot is unsupported")
	// ErrArchiveProjectionForbidden prevents generic serialization of anchors.
	ErrArchiveProjectionForbidden = errors.New("evidence archive projection serialization is forbidden")
	// ErrArchiveExistingLimit is the fixed trusted-policy resource rejection.
	ErrArchiveExistingLimit = errors.New("evidence existing snapshot exceeds trusted limit")
)

// ArchiveExistingReadLimits is supplied only by the future package-private
// subscription adapter. Zero never means unlimited.
type ArchiveExistingReadLimits struct {
	MaxLogBytes uint64
	MaxEvents   uint64
}

// ArchivePosixIdentity is the fixed scalar projection required by the sealed
// archive wire. It contains no path or source payload.
type ArchivePosixIdentity struct {
	Device    uint64
	Inode     uint64
	Mode      uint32
	UID       uint32
	GID       uint32
	LinkCount uint64
}

type ArchiveDirectoryAnchor struct {
	Identity       ArchivePosixIdentity
	EntryCount     uint32
	EntrySetSHA256 [32]byte
}

type ArchiveFileAnchor struct {
	Identity ArchivePosixIdentity
	Length   uint64
	SHA256   [32]byte
}

// ArchiveEvidenceAnchor is a by-value projection cached only after Open has
// fully verified the existing evidence store.
type ArchiveEvidenceAnchor struct {
	Root            ArchiveDirectoryAnchor
	Lock            ArchiveFileAnchor
	Log             ArchiveFileAnchor
	Checkpoint      ArchiveFileAnchor
	EventCount      uint64
	EventHead       [32]byte
	CheckpointCount uint64
	CheckpointHead  [32]byte
}

// ExistingArchiveSnapshot owns retained existing-only descriptors and a
// single immutable Open-time anchor. Platform state is selected by build tag.
type ExistingArchiveSnapshot struct {
	anchor ArchiveEvidenceAnchor
	state  *existingArchiveSnapshotState
}

// Anchor is deliberately infallible and performs no I/O or lazy validation.
func (s *ExistingArchiveSnapshot) Anchor() ArchiveEvidenceAnchor {
	if s == nil {
		return ArchiveEvidenceAnchor{}
	}
	return s.anchor
}

// String and GoString keep both pointer and value formatting opaque. The
// receiver copies only the fixed anchor and a private-state pointer; it never
// copies an active mutex, takes a lock, or performs source I/O.
func (ExistingArchiveSnapshot) String() string {
	return "evidence.ExistingArchiveSnapshot<redacted>"
}

func (ExistingArchiveSnapshot) GoString() string {
	return "evidence.ExistingArchiveSnapshot<redacted>"
}

func (ArchivePosixIdentity) String() string { return "evidence.ArchivePosixIdentity<redacted>" }
func (ArchivePosixIdentity) GoString() string {
	return "evidence.ArchivePosixIdentity<redacted>"
}
func (ArchiveDirectoryAnchor) String() string { return "evidence.ArchiveDirectoryAnchor<redacted>" }
func (ArchiveDirectoryAnchor) GoString() string {
	return "evidence.ArchiveDirectoryAnchor<redacted>"
}
func (ArchiveFileAnchor) String() string { return "evidence.ArchiveFileAnchor<redacted>" }
func (ArchiveFileAnchor) GoString() string {
	return "evidence.ArchiveFileAnchor<redacted>"
}
func (ArchiveEvidenceAnchor) String() string { return "evidence.ArchiveEvidenceAnchor<redacted>" }
func (ArchiveEvidenceAnchor) GoString() string {
	return "evidence.ArchiveEvidenceAnchor<redacted>"
}
func (ArchiveExistingReadLimits) String() string {
	return "evidence.ArchiveExistingReadLimits<redacted>"
}
func (ArchiveExistingReadLimits) GoString() string {
	return "evidence.ArchiveExistingReadLimits<redacted>"
}
func (ArchivePosixIdentity) MarshalJSON() ([]byte, error) {
	return nil, ErrArchiveProjectionForbidden
}
func (ArchiveDirectoryAnchor) MarshalJSON() ([]byte, error) {
	return nil, ErrArchiveProjectionForbidden
}
func (ArchiveFileAnchor) MarshalJSON() ([]byte, error) { return nil, ErrArchiveProjectionForbidden }
func (ArchiveEvidenceAnchor) MarshalJSON() ([]byte, error) {
	return nil, ErrArchiveProjectionForbidden
}
func (ArchiveExistingReadLimits) MarshalJSON() ([]byte, error) {
	return nil, ErrArchiveProjectionForbidden
}
func (*ArchivePosixIdentity) UnmarshalJSON([]byte) error { return ErrArchiveProjectionForbidden }
func (*ArchiveDirectoryAnchor) UnmarshalJSON([]byte) error {
	return ErrArchiveProjectionForbidden
}
func (*ArchiveFileAnchor) UnmarshalJSON([]byte) error { return ErrArchiveProjectionForbidden }
func (*ArchiveEvidenceAnchor) UnmarshalJSON([]byte) error {
	return ErrArchiveProjectionForbidden
}
func (*ArchiveExistingReadLimits) UnmarshalJSON([]byte) error {
	return ErrArchiveProjectionForbidden
}
func (ArchivePosixIdentity) MarshalText() ([]byte, error) {
	return nil, ErrArchiveProjectionForbidden
}
func (ArchiveDirectoryAnchor) MarshalText() ([]byte, error) {
	return nil, ErrArchiveProjectionForbidden
}
func (ArchiveFileAnchor) MarshalText() ([]byte, error) { return nil, ErrArchiveProjectionForbidden }
func (ArchiveEvidenceAnchor) MarshalText() ([]byte, error) {
	return nil, ErrArchiveProjectionForbidden
}
func (ArchiveExistingReadLimits) MarshalText() ([]byte, error) {
	return nil, ErrArchiveProjectionForbidden
}
func (*ArchivePosixIdentity) UnmarshalText([]byte) error { return ErrArchiveProjectionForbidden }
func (*ArchiveDirectoryAnchor) UnmarshalText([]byte) error {
	return ErrArchiveProjectionForbidden
}
func (*ArchiveFileAnchor) UnmarshalText([]byte) error { return ErrArchiveProjectionForbidden }
func (*ArchiveEvidenceAnchor) UnmarshalText([]byte) error {
	return ErrArchiveProjectionForbidden
}
func (*ArchiveExistingReadLimits) UnmarshalText([]byte) error {
	return ErrArchiveProjectionForbidden
}
