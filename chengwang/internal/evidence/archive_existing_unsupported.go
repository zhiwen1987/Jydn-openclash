//go:build !linux

package evidence

type existingArchiveSnapshotState struct{}

func OpenExistingArchiveSnapshot(string, ArchiveExistingReadLimits) (*ExistingArchiveSnapshot, error) {
	return nil, ErrArchiveExistingUnsupported
}

func (s *ExistingArchiveSnapshot) Revalidate() error {
	if s == nil {
		return ErrStoreClosed
	}
	return ErrArchiveExistingUnsupported
}

func (s *ExistingArchiveSnapshot) Close() error { return nil }
