//go:build !linux

package restorecurrent

import "chengwang/internal/restorelease"

type platformSnapshot struct{}

func openPlatform(string, restorelease.Identity) (*platformSnapshot, configurationContents, error) {
	return nil, configurationContents{}, ErrUnsupported
}

func (*platformSnapshot) verify() error { return ErrUnsupported }
func (*platformSnapshot) close() error  { return nil }
