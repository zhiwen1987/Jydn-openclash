//go:build linux && chengwang_mihomo_service

package mihomodeploy

// Acceptance-only, fixed-path, read-only projection. Normal product builds do
// not contain this function. No owner nonce, permit, credential or private YAML
// is exported; the full private WAL is validated by its actual product codec.
import (
	"errors"
	"io"
	"os"
	"syscall"
	"time"
)

type LabAcceptanceArchive struct {
	OperationID string `json:"operationId"`
	PlanSHA256 string `json:"planSHA256"`
	IntentSHA256 *string `json:"intentSHA256"`
	Phase string `json:"phase"`
	HeadSHA256 string `json:"headSHA256"`
	Generation uint64 `json:"generation"`
	CommitRevision uint64 `json:"commitRevision"`
	CommittedAt time.Time `json:"committedAt"`
	Transport *LabTransportView `json:"transport"`
}

type LabAcceptanceState struct {
	Schema string `json:"schema"`
	SourceCommit string `json:"sourceCommit"`
	WALSchema string `json:"walSchema"`
	ControlSHA256 string `json:"controlSHA256"`
	RecordSHA256 string `json:"recordSHA256"`
	Head LabHeadView `json:"head"`
	ActiveOperationID *string `json:"activeOperationId"`
	ActivePhase *string `json:"activePhase"`
	ActiveIntentSHA256 *string `json:"activeIntentSHA256"`
	Completed []LabAcceptanceArchive `json:"completed"`
	Terminated []LabAcceptanceArchive `json:"terminated"`
	UnknownObservationCount int `json:"unknownObservationCount"`
	PrivateWALValidated bool `json:"privateWALValidated"`
	FullPrivateWALIndependentlyProven bool `json:"fullPrivateWALIndependentlyProven"`
	ObservedProcessMatchesHead bool `json:"observedProcessMatchesHead"`
	Production bool `json:"production"`
}

func labAcceptanceArchive(a lifecycleActive, h lifecycleHead, revision uint64, at time.Time) LabAcceptanceArchive {
	v := LabAcceptanceArchive{OperationID: a.Plan.OperationID, PlanSHA256: a.Plan.PlanSHA256, Phase: a.Phase,
		HeadSHA256: h.HeadSHA256, Generation: h.Generation, CommitRevision: revision, CommittedAt: at}
	if a.Intent != nil { value := a.Intent.IntentSHA256; v.IntentSHA256 = &value }
	if a.Result != nil {
		v.Transport = &LabTransportView{Result: a.Result.Reload, RecordedAt: a.Result.ObservedAt, Origin: a.Result.Origin}
		if a.Result.ServiceGate != nil { value := a.Result.ServiceGate.Reason; v.Transport.GateReason = &value }
	}
	return v
}

// This read never opens the writer or acquires/changes its lock. The WAL is
// intentionally writable; ELF/receipt's labKernelFile RO policy is unrelated.
func labAcceptanceControl() ([]byte, string, error) {
	reject := errors.New("isolated laboratory acceptance state unavailable")
	if os.Geteuid() != 10001 || os.Getegid() != 10001 { return nil, "", reject }
	probe := &lifecycleLinuxDisk{lifecycleLinuxDiskCore: &lifecycleLinuxDiskCore{uid: 10001, gid: 10001}}
	chain, err := probe.openChain(labWALPath, true, false)
	if err != nil { return nil, "", reject }
	defer func() { for i := len(chain)-1; i >= 0; i-- { _ = chain[i].file.Close() } }()
	parent := chain[len(chain)-1]
	f, err := artifactOpen(parent.file, "control.json", syscall.O_RDONLY, 0)
	if err != nil { return nil, "", reject }
	defer f.Close()
	before, statErr := artifactStat(f)
	mount, mountErr := lifecycleMountID(f)
	if statErr != nil || mountErr != nil || !probe.fileSafe(before, false) || mount != parent.mount ||
		probe.checkChain(chain) != nil || probe.named(parent.file, "control.json", before, mount, true) != nil { return nil, "", reject }
	raw, err := io.ReadAll(io.LimitReader(f, maxLifecycleControlBytes+1))
	after, statErr := artifactStat(f)
	if err != nil || statErr != nil || int64(len(raw)) != before.Size || !artifactSame(before, after, true) ||
		probe.checkChain(chain) != nil || probe.named(parent.file, "control.json", after, mount, true) != nil { return nil, "", reject }
	return raw, labConfigHash(raw), nil
}

func ReadIsolatedLabAcceptanceState() (LabAcceptanceState, error) {
	var zero LabAcceptanceState
	reject := errors.New("isolated laboratory acceptance state unavailable")
	raw, digest, err := labAcceptanceControl()
	if err != nil { return zero, reject }
	r, err := decodeLifecycleRecord(raw)
	if err != nil || r.wire == nil || r.wire.Schema != lifecycleSchemaV2 || r.wire.V2 == nil || r.wire.Head == nil { return zero, reject }
	w, h := r.wire, r.wire.Head
	input, err := openLabKernelInput()
	if err != nil { return zero, reject }
	observed, err := labKernelObserve(h.PID, input)
	if err != nil || observed.StartTicks != h.StartTicks || observed.NetNSInode != h.NetNSInode ||
		observed.ELFSHA256 != h.KernelSHA256 || h.ControllerPort != 28412 || h.MixedPort != 28411 { return zero, reject }
	// Observing an actual process here does not adopt it or produce an owned
	// handle. It is an independent postcondition against the private head.
	// Commit belongs to the verified immutable input receipt, not /proc.
	v := LabAcceptanceState{Schema: "chengwang.mihomo-lab-acceptance-state/v1", SourceCommit: input.commit,
		WALSchema: w.Schema, ControlSHA256: digest, RecordSHA256: w.RecordSHA256,
		Completed: []LabAcceptanceArchive{}, Terminated: []LabAcceptanceArchive{},
		UnknownObservationCount: len(w.V2.Observations), PrivateWALValidated: true, ObservedProcessMatchesHead: true}
	v.Head = LabHeadView{Schema: LabHeadViewSchema, Boundary: LabBackendBoundary, Revision: w.Revision, Generation: h.Generation,
		HeadSHA256: h.HeadSHA256, ArtifactRecordSHA256: h.Artifact.RecordSHA256, ConfigSHA256: h.Artifact.Config.SHA256,
		VerificationSHA256: h.VerificationSHA256, VerifiedAt: h.VerifiedAt}
	if h.PreviousHeadSHA256 != nil { value := *h.PreviousHeadSHA256; v.Head.PreviousHeadSHA256 = &value }
	if a := w.Active; a != nil {
		id, phase := a.Plan.OperationID, a.Phase
		v.ActiveOperationID, v.ActivePhase, v.Head.ActiveOperationID = &id, &phase, &id
		if a.Intent != nil { value := a.Intent.IntentSHA256; v.ActiveIntentSHA256 = &value }
		v.Head.WriteBlocked = a.Phase == "UNKNOWN" || a.Phase == "MANUAL_REQUIRED" || a.Phase == "DISPATCH_ARMED" || a.Phase == "ACKNOWLEDGED" || a.Phase == "RESPONSE_REJECTED"
	}
	for _, a := range w.V2.Completed { v.Completed = append(v.Completed, labAcceptanceArchive(a.Active, a.Head, a.CommitRevision, a.CommittedAt)) }
	for _, a := range w.V2.Terminated { v.Terminated = append(v.Terminated, labAcceptanceArchive(a.Active, a.Head, a.CommitRevision, a.CommittedAt)) }
	return v, nil
}
