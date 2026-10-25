package mihomodeploy

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"sync"
	"time"
)

const labQuiescenceObservationSchema = "chengwang.mihomo-owned-quiescence-observation/v1"
const labQuiescenceFactSchema = "chengwang.mihomo-owned-quiescence-fact/v1"
const labQuiescenceDebug = "private owned-epoch quiescence observation; not authorization"
const maxLabQuiescenceClaims = 64

var errLabQuiescence = errors.New("owned laboratory quiescence is not proven")
var labQuiescenceID = regexp.MustCompile(`^labrec_[a-f0-9]{32}$`)
var labQuiescenceCommit = regexp.MustCompile(`^[a-f0-9]{40}$`)

// This associates physical observations with an already-armed recovery step.
// It carries no approval: the outer authority/WAL coordinator is not wired here.
// OldEpochSHA256 belongs to that coordinator's scope/provisioning-aware epoch
// codec. It is deliberately not recomputed from ExpectedOldIdentity alone.
type labQuiescenceBinding struct {
	RecoveryID          string            `json:"recoveryId"`
	RecoveryPlanSHA256  string            `json:"recoveryPlanSHA256"`
	StopIntentSHA256    string            `json:"stopIntentSHA256"`
	OldEpochSHA256      string            `json:"oldEpochSHA256"`
	ExpectedOldIdentity labKernelIdentity `json:"expectedOldIdentity"`
	ArmedAt             time.Time         `json:"armedAt"`
	ExpiresAt           time.Time         `json:"expiresAt"`
}

type labQuiescenceProbe struct {
	Port      uint16 `json:"port"`
	Attempted bool   `json:"attempted"`
	Result    string `json:"result"`
}

// Null means not observed. StopInvoked counts entry into the original stop
// method, not a signal, server receipt, authorization, or restored service.
type labQuiescenceObservation struct {
	Schema          string               `json:"schema"`
	StartupIdentity *labKernelIdentity   `json:"startupIdentity"`
	StopInvoked     bool                 `json:"stopInvoked"`
	StopReturned    bool                 `json:"stopReturned"`
	StopErrorClass  *string              `json:"stopErrorClass"`
	Stop            *labKernelExit       `json:"stop"`
	NamespaceInode  *uint64              `json:"namespaceInode"`
	ControllerProbe *labQuiescenceProbe  `json:"controllerProbe"`
	MixedProbe      *labQuiescenceProbe  `json:"mixedProbe"`
	StartedAt       *time.Time           `json:"startedAt"`
	ReturnedAt      *time.Time           `json:"returnedAt"`
	Outcome         string               `json:"outcome"`
	FailureCode     string               `json:"failureCode"`
}

type labQuiescenceFact struct {
	Schema           string                    `json:"schema"`
	Binding          labQuiescenceBinding      `json:"binding"`
	Observation      labQuiescenceObservation  `json:"observation"`
	ObservedAt       time.Time                 `json:"observedAt"`
	QuiescenceSHA256 string                    `json:"quiescenceSHA256"`
}

type labQuiescenceIssuer struct {
	mu      sync.Mutex
	claimed map[*ownedLabKernelCore]bool
	issued  map[*labQuiescedEpochCore]bool
}

var processLabQuiescenceIssuer = labQuiescenceIssuer{
	claimed: map[*ownedLabKernelCore]bool{},
	issued:  map[*labQuiescedEpochCore]bool{},
}

type labQuiescedEpochCore struct {
	issuer *labQuiescenceIssuer
	owner  *ownedLabKernel
	ownerCore *ownedLabKernelCore
	seal   *labQuiescenceOwnerSeal
	nonce  [32]byte
	fact   labQuiescenceFact
}

// Value copies alias this same one-use registry entry, not another capability.
type labQuiescedEpoch struct{ core *labQuiescedEpochCore }

func (i *labQuiescenceIssuer) claim(owner *ownedLabKernelCore) bool {
	if i == nil || owner == nil {
		return false
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.claimed == nil || i.issued == nil || i.claimed[owner] || len(i.claimed) >= maxLabQuiescenceClaims {
		return false
	}
	i.claimed[owner] = true
	return true
}

func (labQuiescedEpoch) String() string   { return labQuiescenceDebug }
func (labQuiescedEpoch) GoString() string { return labQuiescenceDebug }
func (labQuiescedEpoch) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, labQuiescenceDebug)
}
func (labQuiescedEpoch) MarshalJSON() ([]byte, error) {
	return []byte(`{"scope":"OWNED_QUIESCENCE_FACT_NOT_AUTHORIZATION"}`), nil
}
func (*labQuiescedEpoch) UnmarshalJSON([]byte) error { return errLabQuiescence }

func labQuiescenceIdentityValid(v labKernelIdentity) bool {
	return v.PID >= 2 && v.PID <= 1<<31-1 && v.StartTicks > 0 && v.StartTicks <= 1<<63-1 &&
		v.NetNSInode > 0 && v.NetNSInode <= 1<<63-1 && lifecycleNonzeroHash(v.ELFSHA256) &&
		v.ELFBytes >= 64 && v.ELFBytes <= 128<<20 && labQuiescenceCommit.MatchString(v.SourceCommit) &&
		v.SourceCommit != "0000000000000000000000000000000000000000" && lifecycleNonzeroHash(v.ArtifactSHA256) &&
		v.ControllerPort == 28412 && v.MixedPort == 28411
}

func labQuiescenceBindingValid(b labQuiescenceBinding, now time.Time) bool {
	return labQuiescenceID.MatchString(b.RecoveryID) && lifecycleNonzeroHash(b.RecoveryPlanSHA256) &&
		lifecycleNonzeroHash(b.StopIntentSHA256) && lifecycleNonzeroHash(b.OldEpochSHA256) &&
		labQuiescenceIdentityValid(b.ExpectedOldIdentity) && lifecycleTime(now) && lifecycleTime(b.ArmedAt) &&
		lifecycleTime(b.ExpiresAt) && b.ExpiresAt.After(b.ArmedAt) && b.ExpiresAt.Sub(b.ArmedAt) <= 5*time.Minute &&
		!now.Before(b.ArmedAt) && now.Before(b.ExpiresAt)
}

func labQuiescenceExitComplete(v labKernelExit) bool {
	return labQuiescenceExitTerminal(v) && labQuiescenceStreamComplete(v.Stdout) && labQuiescenceStreamComplete(v.Stderr)
}

func labQuiescenceExitTerminal(v labKernelExit) bool {
	if !v.Started || !v.WaitReturned || v.GroupAbsent == nil || !*v.GroupAbsent {
		return false
	}
	if v.WaitErrorClass == "NONE" {
		return v.ExitCode != nil && *v.ExitCode == 0 && v.Signal == nil
	}
	if v.WaitErrorClass != "EXIT_STATUS" {
		return false
	}
	return v.ExitCode != nil && *v.ExitCode >= 1 && *v.ExitCode <= 255 && v.Signal == nil ||
		v.ExitCode == nil && v.Signal != nil && *v.Signal >= 1 && *v.Signal <= 64
}

func labQuiescenceStreamComplete(v labKernelStream) bool {
	return v.Complete && !v.Truncated && v.Bytes >= 0 && v.Bytes <= 64<<10 &&
		v.TotalBytes == int64(v.Bytes) && lifecycleNonzeroHash(v.SHA256)
}

// The original writer drains/hashes/counts the entire stream even after its
// raw retention cap. EOF and raw retention are separate facts. This permits
// no missing EOF, bad total, unknown digest or arbitrary partial prefix.
func labQuiescenceStreamDrained(v labKernelStream) bool {
	if !v.Complete || v.Bytes < 0 || v.Bytes > 64<<10 || !lifecycleNonzeroHash(v.SHA256) {
		return false
	}
	if v.Truncated {
		return v.Bytes == 64<<10 && v.TotalBytes > int64(v.Bytes)
	}
	return v.TotalBytes == int64(v.Bytes)
}

func labQuiescenceExitDrained(v labKernelExit) bool {
	return labQuiescenceExitTerminal(v) && labQuiescenceStreamDrained(v.Stdout) && labQuiescenceStreamDrained(v.Stderr)
}

func labQuiescenceCaptureLimited(v labKernelExit) bool {
	return labQuiescenceExitDrained(v) && (v.Stdout.Truncated || v.Stderr.Truncated)
}

func labQuiescenceStopClassValid(o labQuiescenceObservation) bool {
	if o.Stop == nil || o.StopErrorClass == nil {
		return false
	}
	switch *o.StopErrorClass {
	case "NONE":
		return labQuiescenceExitComplete(*o.Stop)
	case "CAPTURE_LIMIT_ONLY":
		return labQuiescenceCaptureLimited(*o.Stop)
	default:
		return false
	}
}

func labQuiescenceCloneObservation(v labQuiescenceObservation) labQuiescenceObservation {
	if v.StartupIdentity != nil { n := *v.StartupIdentity; v.StartupIdentity = &n }
	if v.StopErrorClass != nil { n := *v.StopErrorClass; v.StopErrorClass = &n }
	if v.Stop != nil { n := labQuiescenceCloneExit(*v.Stop); v.Stop = &n }
	if v.NamespaceInode != nil { n := *v.NamespaceInode; v.NamespaceInode = &n }
	if v.ControllerProbe != nil { n := *v.ControllerProbe; v.ControllerProbe = &n }
	if v.MixedProbe != nil { n := *v.MixedProbe; v.MixedProbe = &n }
	if v.StartedAt != nil { n := *v.StartedAt; v.StartedAt = &n }
	if v.ReturnedAt != nil { n := *v.ReturnedAt; v.ReturnedAt = &n }
	return v
}

func labQuiescenceCloneExit(v labKernelExit) labKernelExit {
	if v.ExitCode != nil { n := *v.ExitCode; v.ExitCode = &n }
	if v.Signal != nil { n := *v.Signal; v.Signal = &n }
	if v.GroupAbsent != nil { n := *v.GroupAbsent; v.GroupAbsent = &n }
	return v
}

func labQuiescenceFactHash(v labQuiescenceFact) (string, error) {
	// Fixed struct order, json.Marshal default escaping, no trailing LF/self hash.
	raw, err := json.Marshal(struct {
		Schema      string                   `json:"schema"`
		Binding     labQuiescenceBinding     `json:"binding"`
		Observation labQuiescenceObservation `json:"observation"`
		ObservedAt  time.Time                `json:"observedAt"`
	}{v.Schema, v.Binding, v.Observation, v.ObservedAt})
	if err != nil { return "", errLabQuiescence }
	return labConfigHash(raw), nil
}

func labQuiescenceFactValid(v labQuiescenceFact, b labQuiescenceBinding, now time.Time) bool {
	o := v.Observation
	if v.Schema != labQuiescenceFactSchema || v.Binding != b || !labQuiescenceBindingValid(b, now) ||
		!lifecycleTime(v.ObservedAt) || v.ObservedAt.After(now) || now.Sub(v.ObservedAt) > 30*time.Second ||
		o.Schema != labQuiescenceObservationSchema || o.Outcome != "QUIESCED" || o.FailureCode != "NONE" ||
		o.StartupIdentity == nil || *o.StartupIdentity != b.ExpectedOldIdentity || !o.StopInvoked || !o.StopReturned ||
		!labQuiescenceStopClassValid(o) || o.NamespaceInode == nil || *o.NamespaceInode != b.ExpectedOldIdentity.NetNSInode ||
		o.StartedAt == nil || o.ReturnedAt == nil || !lifecycleTime(*o.StartedAt) || !lifecycleTime(*o.ReturnedAt) ||
		o.StartedAt.Before(b.ArmedAt) || o.ReturnedAt.Before(*o.StartedAt) || !o.ReturnedAt.Before(b.ExpiresAt) ||
		!v.ObservedAt.Equal(*o.ReturnedAt) {
		return false
	}
	for _, row := range []struct { probe *labQuiescenceProbe; port uint16 }{{o.ControllerProbe, 28412}, {o.MixedProbe, 28411}} {
		if row.probe == nil || row.probe.Port != row.port || !row.probe.Attempted || row.probe.Result != "CONNECTION_REFUSED" {
			return false
		}
	}
	want, err := labQuiescenceFactHash(v)
	return err == nil && lifecycleNonzeroHash(v.QuiescenceSHA256) && want == v.QuiescenceSHA256
}

func (q *labQuiescedEpoch) consumeQuiescence(b labQuiescenceBinding, now time.Time) (labQuiescenceFact, error) {
	var zero labQuiescenceFact
	if q == nil || q.core == nil || q.core.issuer == nil {
		return zero, errLabQuiescence
	}
	x := q.core
	i := x.issuer
	i.mu.Lock()
	defer i.mu.Unlock()
	if !i.issued[x] {
		return zero, errLabQuiescence
	}
	// Every admitted attempt consumes this exact entry, including bad binding,
	// expiry, owner drift and clock failures. Copies can never replay it.
	delete(i.issued, x)
	if x.nonce == ([32]byte{}) || x.owner == nil || x.ownerCore == nil || x.owner.ownedLabKernelCore != x.ownerCore ||
		!i.claimed[x.ownerCore] || x.seal == nil ||
		!labQuiescenceFactValid(x.fact, b, now) || !labQuiescenceOwnerSettled(x.owner, x.seal, b, *x.fact.Observation.Stop) {
		return zero, errLabQuiescence
	}
	v := x.fact
	v.Observation = labQuiescenceCloneObservation(v.Observation)
	return v, nil
}

// This consumes authentic issued evidence for recording only. Freshness is
// checked at the original issuance time, not restored by a late receiver. The
// coordinator must independently apply current strict freshness, approval,
// lease and phase checks before granting any Start provenance. This method
// creates no new handle, owner, permit, probe, stop or dispatch permission.
func (q *labQuiescedEpoch) consumeQuiescenceForRecord(b labQuiescenceBinding, now time.Time) (labQuiescenceFact, error) {
	var zero labQuiescenceFact
	if q == nil || q.core == nil || q.core.issuer == nil {
		return zero, errLabQuiescence
	}
	x := q.core
	i := x.issuer
	i.mu.Lock()
	defer i.mu.Unlock()
	if !i.issued[x] {
		return zero, errLabQuiescence
	}
	// Recording shares the very same single-use entry with strict consumption.
	// Invalid binding, owner or receiving clock still spends that entry.
	delete(i.issued, x)
	if !lifecycleTime(now) || !lifecycleTime(x.fact.ObservedAt) || now.Before(x.fact.ObservedAt) ||
		x.nonce == ([32]byte{}) || x.owner == nil || x.ownerCore == nil || x.owner.ownedLabKernelCore != x.ownerCore ||
		!i.claimed[x.ownerCore] || x.seal == nil || !labQuiescenceFactValid(x.fact, b, x.fact.ObservedAt) ||
		!labQuiescenceOwnerSettled(x.owner, x.seal, b, *x.fact.Observation.Stop) {
		return zero, errLabQuiescence
	}
	v := x.fact
	v.Observation = labQuiescenceCloneObservation(v.Observation)
	return v, nil
}

func labQuiescenceExitEqual(a, b labKernelExit) bool {
	return reflect.DeepEqual(a, b)
}
