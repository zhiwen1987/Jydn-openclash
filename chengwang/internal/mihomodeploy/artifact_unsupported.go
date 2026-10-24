//go:build !linux

package mihomodeploy

func openArtifactDisk(string) (artifactDisk, error) { return nil, ErrArtifactUnsupported }
