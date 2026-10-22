//go:build !linux

package truststate

import "os"

type platformStore struct{}

func openPlatform(string, bool, string, string) (*platformStore, error) { return nil, ErrUnsupported }
func (*platformStore) openDatabase(string, int, os.FileMode) (*os.File, error) {
	return nil, ErrUnsupported
}
func (*platformStore) finishCreate() error { return ErrUnsupported }
func (*platformStore) verify() error       { return ErrUnsupported }
func (*platformStore) close() error        { return nil }
