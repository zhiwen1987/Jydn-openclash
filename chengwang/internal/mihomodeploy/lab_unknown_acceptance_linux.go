//go:build linux && chengwang_mihomo_service && chengwang_mihomo_faults

package mihomodeploy

import (
	"errors"
	"time"
)

// LabUnknownDurableObservation is the last actual matching WAL observation.
// Its conclusion is the durable read-only conclusion, not a rewritten adapter
// result or proof that an uncertain request has become quiescent.
type LabUnknownDurableObservation struct {
	OperationID    string    `json:"operationId"`
	PlanSHA256     string    `json:"planSHA256"`
	IntentSHA256   string    `json:"intentSHA256"`
	Conclusion     string    `json:"conclusion"`
	EvidenceSHA256 string    `json:"evidenceSHA256"`
	ObservedAt     time.Time `json:"observedAt"`
	CommitRevision uint64    `json:"commitRevision"`
}

// LabUnknownAcceptanceState adds only actual private-WAL facts to the existing
// acceptance projection. It contains no live owner, nonce, credential, payload
// or new authority. Missing original transport/observation remains nil.
type LabUnknownAcceptanceState struct {
	State           LabAcceptanceState            `json:"state"`
	ActiveAttempt   int                           `json:"activeAttempt"`
	ActiveTransport *LabTransportView             `json:"activeTransport"`
	LastObservation *LabUnknownDurableObservation `json:"lastObservation"`
}

// ReadIsolatedLabUnknownAcceptanceState is compiled only for the isolated
// fault-acceptance experiment. Both reads use the existing fixed-path custody
// reader; their control digests must agree. This does not open a writer, adopt
// a process, change a head, restore a live capability, or prove full private WAL
// correctness independently of the product decoder.
func ReadIsolatedLabUnknownAcceptanceState() (LabUnknownAcceptanceState, error) {
	var zero LabUnknownAcceptanceState
	reject := errors.New("isolated laboratory unknown acceptance state unavailable")
	raw, digest, err := labAcceptanceControl()
	if err != nil {
		return zero, reject
	}
	r, err := decodeLifecycleRecord(raw)
	if err != nil || r.wire == nil || r.wire.Schema != lifecycleSchemaV2 || r.wire.V2 == nil ||
		r.wire.Active == nil || r.wire.Active.Phase != "UNKNOWN" || r.wire.Active.Intent == nil {
		return zero, reject
	}
	state, err := ReadIsolatedLabAcceptanceState()
	if err != nil || state.ControlSHA256 != digest || state.RecordSHA256 != r.wire.RecordSHA256 ||
		state.WALSchema != lifecycleSchemaV2 || state.ActiveOperationID == nil ||
		*state.ActiveOperationID != r.wire.Active.Plan.OperationID || state.ActivePhase == nil ||
		*state.ActivePhase != "UNKNOWN" || state.ActiveIntentSHA256 == nil ||
		*state.ActiveIntentSHA256 != r.wire.Active.Intent.IntentSHA256 ||
		state.UnknownObservationCount != len(r.wire.V2.Observations) {
		return zero, reject
	}
	a := r.wire.Active
	v := LabUnknownAcceptanceState{State: state, ActiveAttempt: a.Attempt}
	if a.Result != nil {
		v.ActiveTransport = &LabTransportView{Result: a.Result.Reload, RecordedAt: a.Result.ObservedAt, Origin: a.Result.Origin}
		if a.Result.ServiceGate != nil {
			reason := a.Result.ServiceGate.Reason
			v.ActiveTransport.GateReason = &reason
		}
	}
	for i := len(r.wire.V2.Observations) - 1; i >= 0; i-- {
		o := r.wire.V2.Observations[i]
		if o.OperationID == a.Plan.OperationID && o.PlanSHA256 == a.Plan.PlanSHA256 &&
			o.IntentSHA256 == a.Intent.IntentSHA256 {
			v.LastObservation = &LabUnknownDurableObservation{OperationID: o.OperationID,
				PlanSHA256: o.PlanSHA256, IntentSHA256: o.IntentSHA256, Conclusion: o.Readback.Conclusion,
				EvidenceSHA256: o.Readback.EvidenceSHA256, ObservedAt: o.Readback.ObservedAt,
				CommitRevision: o.CommitRevision}
			break
		}
	}
	return v, nil
}
