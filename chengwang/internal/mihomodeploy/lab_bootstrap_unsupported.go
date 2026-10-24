//go:build !linux

package mihomodeploy

func openLabRuntimeDisk() (labRuntimeDisk,bool,error) { return nil,false,errLifecycleUnsupported }
