package mihomodeploy

import (
	"context"
	"time"

	"chengwang/internal/adapter/mihomo"
	"chengwang/internal/authz"
)

const LabBackendBoundary = "OWNED_ISOLATED_MIHOMO_LIFECYCLE_NOT_PRODUCTION_OR_FULL_PAYLOAD_PROOF"
const LabDeploymentViewSchema = "chengwang.mihomo-lab-deployment-view/v1"
const LabHeadViewSchema = "chengwang.mihomo-lab-head-view/v1"
const LabCandidateListViewSchema = "chengwang.mihomo-lab-candidates-view/v1"

// Scope is a detached fixed resource description, never an authorization.
// Every method must authenticate the original Authorization values against
// the current manager before exposing existence or private durable state.
// Request hashes/revisions are comparisons, not permission or owned evidence.
type LabBackend interface {
	Scope() authz.ResourceScope
	Create(context.Context, []string, LabCreateRequest) (LabDeploymentView, error)
	Inspect(context.Context, []string, string) (LabDeploymentView, error)
	Approve(context.Context, []string, string, LabApprovalRequest) (LabDeploymentView, error)
	Execute(context.Context, []string, string, LabExecuteRequest) (LabDeploymentView, error)
	Revoke(context.Context, []string, string, LabRevokeRequest) (LabDeploymentView, error)
	Head(context.Context, []string) (LabHeadView, error)
	Candidates(context.Context, []string) (LabCandidateListView, error)
}

type LabCreateRequest struct {
	CandidateRecordSHA256 string `json:"candidateRecordSHA256"`
	TTLSeconds uint16 `json:"ttlSeconds"`
}
type LabApprovalRequest struct {
	PlanSHA256 string `json:"planSHA256"`
	Revision uint64 `json:"revision"`
}
type LabExecuteRequest struct {
	PlanSHA256 string `json:"planSHA256"`
	Revision uint64 `json:"revision"`
}
type LabRevokeRequest struct {
	PlanSHA256 string `json:"planSHA256"`
	Revision uint64 `json:"revision"`
	Reason string `json:"reason"`
}

// Only the original actual transport result belongs here. A current matching
// projection never changes UNKNOWN to an acknowledged or quiescent request.
type LabTransportView struct {
	Result mihomo.ReloadResult `json:"result"`
	RecordedAt time.Time `json:"recordedAt"`
	Origin string `json:"origin"`
	GateReason *string `json:"gateReason"`
}
type LabObservationView struct {
	Conclusion mihomo.LabReadbackConclusion `json:"conclusion"`
	ObservedProjectionSHA256 *string `json:"observedProjectionSHA256"`
	EvidenceSHA256 string `json:"evidenceSHA256"`
	ObservedAt time.Time `json:"observedAt"`
	LocalRouteVerified bool `json:"localRouteVerified"`
}
type LabProofView struct {
	FullPayloadProven bool `json:"fullPayloadProven"`
	InternetBusinessProven bool `json:"internetBusinessProven"`
	Production bool `json:"production"`
}
type LabDeploymentView struct {
	Schema string `json:"schema"`
	Boundary string `json:"boundary"`
	OperationID string `json:"operationId"`
	Phase string `json:"phase"`
	Revision uint64 `json:"revision"`
	PlanSHA256 string `json:"planSHA256"`
	CandidateRecordSHA256 string `json:"candidateRecordSHA256"`
	CandidateConfigSHA256 string `json:"candidateConfigSHA256"`
	PreviousHeadSHA256 string `json:"previousHeadSHA256"`
	HeadSHA256 string `json:"headSHA256"`
	HeadGeneration uint64 `json:"headGeneration"`
	ExpiresAt time.Time `json:"expiresAt"`
	Transport *LabTransportView `json:"transport"`
	Observation *LabObservationView `json:"observation"`
	WriteBlocked bool `json:"writeBlocked"`
	Replayed bool `json:"replayed"`
	HeadAdvanced bool `json:"headAdvanced"`
	Proof LabProofView `json:"proof"`
}
type LabHeadView struct {
	Schema string `json:"schema"`
	Boundary string `json:"boundary"`
	Revision uint64 `json:"revision"`
	Generation uint64 `json:"generation"`
	HeadSHA256 string `json:"headSHA256"`
	PreviousHeadSHA256 *string `json:"previousHeadSHA256"`
	ArtifactRecordSHA256 string `json:"artifactRecordSHA256"`
	ConfigSHA256 string `json:"configSHA256"`
	VerificationSHA256 string `json:"verificationSHA256"`
	VerifiedAt time.Time `json:"verifiedAt"`
	ActiveOperationID *string `json:"activeOperationId"`
	WriteBlocked bool `json:"writeBlocked"`
	Proof LabProofView `json:"proof"`
}
type LabCandidateView struct {
	Name string `json:"name"`
	RecordSHA256 string `json:"recordSHA256"`
	ConfigSHA256 string `json:"configSHA256"`
	SourceSpecSHA256 string `json:"sourceSpecSHA256"`
	IsCurrent bool `json:"isCurrent"`
}
type LabCandidateListView struct {
	Schema string `json:"schema"`
	Boundary string `json:"boundary"`
	Candidates []LabCandidateView `json:"candidates"`
	WriteBlocked bool `json:"writeBlocked"`
	Proof LabProofView `json:"proof"`
}

// These bounded codes cannot carry raw controller errors, credentials, paths,
// response bodies or a serialized authority. Unknown codes fail closed.
type LabBackendCode uint8
const (
	LabBackendInvalid LabBackendCode = iota + 1
	LabBackendUnauthenticated
	LabBackendForbidden
	LabBackendNotFound
	LabBackendUnavailable
	LabBackendConflict
	LabBackendInternal
)
type LabBackendError struct {
	Code LabBackendCode
	StateMayHaveChanged bool
}
func (*LabBackendError) Error() string { return "Mihomo laboratory backend rejected" }
