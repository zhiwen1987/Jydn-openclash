//go:build !linux

package restoreruntime

func productionClient() (snapshotClient, error) { return nil, ErrUnsupported }
