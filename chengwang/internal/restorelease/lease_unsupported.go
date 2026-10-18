//go:build !linux

package restorelease

type platformLease struct{}

func acquirePlatform(string) (*platformLease, Identity, error) {
	return nil, Identity{}, ErrUnsupported
}

func (*platformLease) verify() error { return ErrUnsupported }
func (*platformLease) close() error  { return nil }
