//go:build !linux

package mihomodeploy

import "context"

type labRecoveryStartedOwnerSeal struct{}

func startOwnedRecoveryKernel(context.Context, *labKernelInput, *ArtifactStore, *labRecoveryStartPermit) (*ownedLabKernel, *labRecoveryStartedEpoch, labRecoveryStartObservation, error) {
	return nil, nil, labRecoveryStartObservation{Schema: labRecoveryStartObservationSchema,
		Outcome: "ENTRY_REJECTED", FailureCode: "PLATFORM_UNSUPPORTED"}, errLabRecoveryStart
}
func startOwnedAbsentRecoveryKernel(context.Context, *labKernelInput, *ArtifactStore, *labRecoveryAbsentStartPermit) (*ownedLabKernel, *labRecoveryStartedEpoch, labRecoveryStartObservation, error) {
	return nil, nil, labRecoveryStartObservation{Schema: labRecoveryAbsentStartObservationSchema,
		Outcome: "ENTRY_REJECTED", FailureCode: "PLATFORM_UNSUPPORTED"}, errLabRecoveryStart
}
func labRecoveryStartedOwnerMatches(*ownedLabKernel, *labRecoveryStartedOwnerSeal, labKernelIdentity) bool {
	return false
}
func labRecoveryStartedOwnerCurrent(*ownedLabKernel, labKernelIdentity) bool { return false }
