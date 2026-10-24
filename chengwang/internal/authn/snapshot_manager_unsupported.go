//go:build !linux

package authn

import (
	"errors"
	"os"
)

func snapshotPlatformSupported() bool { return false }

func openCredentialFile(path string, strict bool) (*os.File, error) {
	if strict {
		return nil, errors.New("credential snapshot platform unsupported")
	}
	return os.Open(path)
}

func credentialMetadata(_ os.FileInfo, strict, _ bool) (credentialOSState, error) {
	if strict {
		return credentialOSState{}, errors.New("credential snapshot platform unsupported")
	}
	// Preserve the existing immutable Open API and its documented Windows ACL
	// boundary. The strict manager never silently takes this fallback.
	return credentialOSState{}, nil
}
