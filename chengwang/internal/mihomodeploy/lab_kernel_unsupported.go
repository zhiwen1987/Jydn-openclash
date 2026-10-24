//go:build !linux

package mihomodeploy

import "context"

type labKernelInputCore struct{}
type ownedLabKernelCore struct{}

func openLabKernelInput() (*labKernelInput,error) { return nil,errLabKernelUnsupported }
func startOwnedLabKernel(context.Context,*labKernelInput,*LabConfigArtifact) (*ownedLabKernel,error) { return nil,errLabKernelUnsupported }
func (*ownedLabKernel) identity() (labKernelIdentity,error) { return labKernelIdentity{},errLabKernelUnsupported }
func (*ownedLabKernel) verifyListeners() error { return errLabKernelUnsupported }
func (*ownedLabKernel) stop(context.Context) (labKernelExit,error) { return labKernelExit{},errLabKernelUnsupported }
func (*ownedLabKernel) startObservation()labKernelStartObservation { return labKernelStartObservation{} }
