//go:build !linux

package mihomodeploy

func openLifecycleDisk() (lifecycleDisk, error) { return nil, errLifecycleUnsupported }
