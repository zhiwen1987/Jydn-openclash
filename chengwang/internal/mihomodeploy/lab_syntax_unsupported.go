//go:build !linux

package mihomodeploy

import "context"

func labServiceSyntax(context.Context,*labKernelInput,*LabConfigArtifact,*labServiceDiagnostics,string) (*labSyntaxCleanupObservation,error){return nil,errLabKernelUnsupported}
