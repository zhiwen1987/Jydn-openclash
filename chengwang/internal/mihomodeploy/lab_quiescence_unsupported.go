//go:build !linux

package mihomodeploy

import "context"

type labQuiescenceOwnerSeal struct{}

func quiesceOwnedLabKernel(context.Context, *ownedLabKernel, labQuiescenceBinding) (*labQuiescedEpoch, labQuiescenceObservation, error) {
	return nil, labQuiescenceObservation{Schema: labQuiescenceObservationSchema,
		Outcome: "ENTRY_REJECTED", FailureCode: "PLATFORM_UNSUPPORTED"}, errLabQuiescence
}

func labQuiescenceOwnerSettled(*ownedLabKernel, *labQuiescenceOwnerSeal, labQuiescenceBinding, labKernelExit) bool {
	return false
}
