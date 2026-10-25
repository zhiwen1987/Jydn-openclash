package mihomodeploy

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"time"
)

const lifecycleSchemaV3 = "chengwang.mihomo-lifecycle-record/v3"
const lifecycleRecoveryDebug = "private structural recovery journal; not authorization"

// V3 is deliberately a separate codec. Neither the old default decoder nor
// its v1/v2 hash material or genesis rules are changed by this extension.
type lifecycleV3Record struct{ core *lifecycleV3Wire }
type lifecycleV3Wire struct {
	Schema            string                  `json:"schema"`
	Boundary          string                  `json:"boundary"`
	Revision          uint64                  `json:"revision"`
	RecordSHA256      string                  `json:"recordSHA256"`
	LastTrustedAt     time.Time               `json:"lastTrustedAt"`
	Provisioning      lifecycleProvisioning   `json:"provisioning"`
	SourceV2          lifecycleLegacySnapshot `json:"sourceV2"`
	Current           lifecycleEpochLedger    `json:"current"`
	RetiredEpochs     []lifecycleRetiredEpoch `json:"retiredEpochs"`
	RecoveryOwner     *lifecycleOwner         `json:"recoveryOwner"`
	LastRecoveryFence uint64                  `json:"lastRecoveryFence"`
	Recovery          *lifecycleRecoveryTxn   `json:"recovery"`
	RecoveryHistory   []lifecycleRecoveryTxn  `json:"recoveryHistory"`
}
type lifecycleLegacySnapshot struct {
	Schema        string `json:"schema"`
	ControlSHA256 string `json:"controlSHA256"`
	RecordSHA256  string `json:"recordSHA256"`
	Revision      uint64 `json:"revision"`
	ControlBytes  []byte `json:"controlBytes"`
}
type lifecycleEpochAnchor struct {
	Kind                string        `json:"kind"`
	InitialHead         lifecycleHead `json:"initialHead"`
	RecoveryID          *string       `json:"recoveryId"`
	SourceControlSHA256 string        `json:"sourceControlSHA256"`
}
type lifecycleEpochLedger struct {
	Anchor       lifecycleEpochAnchor         `json:"anchor"`
	Head         lifecycleHead                `json:"head"`
	Owner        *lifecycleOwner              `json:"owner"`
	LastFence    uint64                       `json:"lastFence"`
	Active       *lifecycleActive             `json:"active"`
	Tombstones   []lifecycleTombstone         `json:"tombstones"`
	Completed    []lifecycleCompletion        `json:"completed"`
	Terminated   []lifecycleTerminalArchive   `json:"terminated"`
	Observations []lifecycleObservationRecord `json:"observations"`
}
type lifecycleRetiredEpoch struct {
	Ledger         lifecycleEpochLedger `json:"ledger"`
	RetiredAt      time.Time            `json:"retiredAt"`
	CommitRevision uint64               `json:"commitRevision"`
	RecoveryID     string               `json:"recoveryId"`
	LedgerSHA256   string               `json:"ledgerSHA256"`
}
type lifecycleRecoveryApproval struct {
	Schema              string    `json:"schema"`
	RecoveryPlanSHA256  string    `json:"recoveryPlanSHA256"`
	DeclaredApproverRef string    `json:"declaredApproverRef"`
	IssuedAt            time.Time `json:"issuedAt"`
	ExpiresAt           time.Time `json:"expiresAt"`
	ApprovalSHA256      string    `json:"approvalSHA256"`
}
type lifecycleRecoveryActionIntent struct {
	Schema             string    `json:"schema"`
	Action             string    `json:"action"`
	RecoveryID         string    `json:"recoveryId"`
	RecoveryPlanSHA256 string    `json:"recoveryPlanSHA256"`
	OwnerFence         uint64    `json:"ownerFence"`
	ArmedAt            time.Time `json:"armedAt"`
	IntentSHA256       string    `json:"intentSHA256"`
}
type lifecycleRecoveryFailure struct {
	Code string    `json:"code"`
	At   time.Time `json:"at"`
}

// This typed terminal shape is structural data only. This first extension has
// no method accepting a DTO to create it or a new head. Actual startup and
// collector capabilities must be connected before that transition exists.
type lifecycleRecoveryCompletion struct {
	PreviousHead   lifecycleHead `json:"previousHead"`
	Head           lifecycleHead `json:"head"`
	EvidenceSHA256 string        `json:"evidenceSHA256"`
	CommitRevision uint64        `json:"commitRevision"`
	CommittedAt    time.Time     `json:"committedAt"`
}
type lifecycleRecoveryTxn struct {
	Plan             labRecoveryPlanDescriptor      `json:"plan"`
	Phase            string                         `json:"phase"`
	Approval         *lifecycleRecoveryApproval     `json:"approval"`
	Revocation       *lifecycleRevocation           `json:"revocation"`
	StopIntent       *lifecycleRecoveryActionIntent `json:"stopIntent"`
	StopBinding      *labQuiescenceBinding          `json:"stopBinding"`
	Quiescence       *labQuiescenceFact             `json:"quiescence"`
	FailedQuiescence []labQuiescenceObservation     `json:"failedQuiescence"`
	StartIntent      *lifecycleRecoveryActionIntent `json:"startIntent"`
	Completion       *lifecycleRecoveryCompletion   `json:"completion"`
	Failure          *lifecycleRecoveryFailure      `json:"failure"`
	UpdatedAt        time.Time                      `json:"updatedAt"`
	Execution        *lifecycleRecoveryExecution    `json:"execution,omitempty"`
}

func (lifecycleV3Record) String() string   { return lifecycleRecoveryDebug }
func (lifecycleV3Record) GoString() string { return lifecycleRecoveryDebug }
func (lifecycleV3Record) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, lifecycleRecoveryDebug)
}
func (lifecycleV3Record) MarshalJSON() ([]byte, error) {
	return []byte(`{"scope":"PRIVATE_RECOVERY_RECORD_NOT_AUTHORIZATION"}`), nil
}
func (r *lifecycleV3Record) UnmarshalJSON([]byte) error {
	if r != nil {
		r.core = nil
	}
	return errLifecycleUnsafe
}

func lifecycleV3RecordHash(w lifecycleV3Wire) (string, error) {
	// Explicit order, excluding only this record's own digest.
	return lifecycleHash(struct {
		Schema            string                  `json:"schema"`
		Boundary          string                  `json:"boundary"`
		Revision          uint64                  `json:"revision"`
		LastTrustedAt     time.Time               `json:"lastTrustedAt"`
		Provisioning      lifecycleProvisioning   `json:"provisioning"`
		SourceV2          lifecycleLegacySnapshot `json:"sourceV2"`
		Current           lifecycleEpochLedger    `json:"current"`
		RetiredEpochs     []lifecycleRetiredEpoch `json:"retiredEpochs"`
		RecoveryOwner     *lifecycleOwner         `json:"recoveryOwner"`
		LastRecoveryFence uint64                  `json:"lastRecoveryFence"`
		Recovery          *lifecycleRecoveryTxn   `json:"recovery"`
		RecoveryHistory   []lifecycleRecoveryTxn  `json:"recoveryHistory"`
	}{w.Schema, w.Boundary, w.Revision, w.LastTrustedAt, w.Provisioning, w.SourceV2, w.Current, w.RetiredEpochs, w.RecoveryOwner, w.LastRecoveryFence, w.Recovery, w.RecoveryHistory})
}
// One top-level strict decode owns one bounded scope. A memo seal is issued only
// from bytes that passed token, typed, root-hash, complete semantic and exact
// canonical-byte checks. Its digest and length are calculated here, never read
// from RecordSHA256 or a caller assertion. A hit repeats the syntax, typed,
// canonical-byte and root-hash checks before it may reuse semantic validation.
// The scope is never stored on a runtime or store.
const (
	maxLifecycleV3DecodeRoots = maxLifecycleHistory*4 + 8
	maxLifecycleV3DecodeDepth = maxLifecycleHistory*4 + 8
	// Every admitted root may check every history entry's Plan and Completion
	// prefix. This bound covers the full 256-entry topology; it does not reduce
	// the existing history capacity.
	maxLifecycleV3DecodeWork = maxLifecycleV3DecodeRoots * (maxLifecycleHistory + 1) * (maxLifecycleHistory*4 + 32)
)

type lifecycleV3DecodeMemoKey struct {
	bytes  int
	sha256 [sha256.Size]byte
}

type lifecycleV3DecodeMemoSeal struct {
	identity     *lifecycleV3DecodeMemoSeal
	scope        *lifecycleV3DecodeScope
	key          lifecycleV3DecodeMemoKey
	schema       string
	boundary     string
	revision     uint64
	recordSHA256 string
}

type lifecycleV3DecodeScope struct {
	memo      map[lifecycleV3DecodeMemoKey]*lifecycleV3DecodeMemoSeal
	active    map[lifecycleV3DecodeMemoKey]bool
	roots     int
	validated int
	memoHits  int
	work      int
	depth     int
}

func newLifecycleV3DecodeScope() *lifecycleV3DecodeScope {
	return &lifecycleV3DecodeScope{memo: map[lifecycleV3DecodeMemoKey]*lifecycleV3DecodeMemoSeal{}, active: map[lifecycleV3DecodeMemoKey]bool{}}
}

func (s *lifecycleV3DecodeScope) charge(n int) error {
	if s == nil || n < 0 || s.work > maxLifecycleV3DecodeWork-n {
		return errLifecycleUnsafe
	}
	s.work += n
	return nil
}

func decodeLifecycleV3Record(raw []byte) (lifecycleV3Record, error) {
	return decodeLifecycleV3RecordScoped(raw, newLifecycleV3DecodeScope())
}

func lifecycleV3DecodeCanonicalSyntax(raw []byte) (lifecycleV3Record, error) {
	if len(raw) == 0 || len(raw) > maxLifecycleControlBytes {
		return lifecycleV3Record{}, errLifecycleUnsafe
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if lifecycleTokens(d, 0) != nil {
		return lifecycleV3Record{}, errLifecycleUnsafe
	}
	if _, err := d.Token(); err != io.EOF {
		return lifecycleV3Record{}, errLifecycleUnsafe
	}
	var w lifecycleV3Wire
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&w) != nil {
		return lifecycleV3Record{}, errLifecycleUnsafe
	}
	canonical, err := json.Marshal(&w)
	if err != nil || !bytes.Equal(canonical, raw) {
		return lifecycleV3Record{}, errLifecycleUnsafe
	}
	return lifecycleV3Record{core: &w}, nil
}

func decodeLifecycleV3RecordScoped(raw []byte, scope *lifecycleV3DecodeScope) (lifecycleV3Record, error) {
	if len(raw) == 0 || len(raw) > maxLifecycleControlBytes {
		return lifecycleV3Record{}, errLifecycleUnsafe
	}
	if scope == nil || scope.memo == nil || scope.active == nil {
		return lifecycleV3Record{}, errLifecycleUnsafe
	}
	key := lifecycleV3DecodeMemoKey{bytes: len(raw), sha256: sha256.Sum256(raw)}
	if seal, ok := scope.memo[key]; ok {
		r, err := lifecycleV3DecodeCanonicalSyntax(raw)
		if err != nil || seal == nil || seal.identity != seal || seal.scope != scope || seal.key != key || r.core == nil ||
			r.core.Schema != seal.schema || r.core.Boundary != seal.boundary || r.core.Revision != seal.revision || r.core.RecordSHA256 != seal.recordSHA256 {
			return lifecycleV3Record{}, errLifecycleUnsafe
		}
		h, err := lifecycleV3RecordHash(*r.core)
		if err != nil || h != r.core.RecordSHA256 || !lifecycleNonzeroHash(h) {
			return lifecycleV3Record{}, errLifecycleUnsafe
		}
		scope.memoHits++
		return r, nil
	}
	if scope.active[key] || scope.roots >= maxLifecycleV3DecodeRoots || scope.depth >= maxLifecycleV3DecodeDepth {
		return lifecycleV3Record{}, errLifecycleUnsafe
	}
	scope.roots++
	scope.active[key] = true
	scope.depth++
	defer func() {
		delete(scope.active, key)
		scope.depth--
	}()
	r, err := lifecycleV3DecodeCanonicalSyntax(raw)
	if err != nil {
		return lifecycleV3Record{}, errLifecycleUnsafe
	}
	if validateLifecycleV3RecordScoped(r, scope) != nil {
		return lifecycleV3Record{}, errLifecycleUnsafe
	}
	seal := &lifecycleV3DecodeMemoSeal{scope: scope, key: key, schema: r.core.Schema, boundary: r.core.Boundary,
		revision: r.core.Revision, recordSHA256: r.core.RecordSHA256}
	seal.identity = seal
	scope.validated++
	scope.memo[key] = seal
	return r, nil
}
func encodeLifecycleV3Record(r lifecycleV3Record) ([]byte, error) {
	return encodeLifecycleV3RecordScoped(r, newLifecycleV3DecodeScope())
}
func encodeLifecycleV3RecordScoped(r lifecycleV3Record, scope *lifecycleV3DecodeScope) ([]byte, error) {
	if validateLifecycleV3RecordScoped(r, scope) != nil {
		return nil, errLifecycleUnsafe
	}
	raw, err := json.Marshal(r.core)
	if err != nil || len(raw) > maxLifecycleControlBytes {
		return nil, errLifecycleUnsafe
	}
	return raw, nil
}

// Only prepareLifecycleCandidate calls this path after its issued-base,
// transition, revision and clock checks. It derives this candidate's own root
// digest exactly once, checks every semantic/history field, then emits bounded
// canonical bytes. No supplied digest, trust flag or cached authority is used.
// External bytes still use the unchanged strict decoder/encoder hash gate.
func sealLifecycleV3Candidate(r lifecycleV3Record) ([]byte, error) {
	w := r.core
	if w == nil || w.Schema != lifecycleSchemaV3 || w.Boundary != lifecycleBoundary || w.Revision == 0 || !lifecycleTime(w.LastTrustedAt) || w.RetiredEpochs == nil || w.RecoveryHistory == nil || len(w.RetiredEpochs) > maxLifecycleHistory || len(w.RecoveryHistory) > maxLifecycleHistory {
		return nil, errLifecycleUnsafe
	}
	h, err := lifecycleV3RecordHash(*w)
	if err != nil || !lifecycleNonzeroHash(h) {
		return nil, errLifecycleUnsafe
	}
	w.RecordSHA256 = h
	if validateLifecycleV3ContentsScoped(w, newLifecycleV3DecodeScope()) != nil {
		return nil, errLifecycleUnsafe
	}
	raw, err := json.Marshal(w)
	if err != nil || len(raw) > maxLifecycleControlBytes {
		return nil, errLifecycleUnsafe
	}
	return raw, nil
}

func lifecycleLegacyLedger(r lifecycleRecord, raw []byte) lifecycleEpochLedger {
	w := r.wire
	initial := *w.Head
	if len(w.V2.Completed) > 0 {
		initial = w.V2.Completed[0].PreviousHead
	}
	return lifecycleEpochLedger{lifecycleEpochAnchor{"LEGACY_V2", initial, nil, labConfigHash(raw)}, *w.Head, w.Owner, w.LastFence, w.Active, w.Tombstones, w.V2.Completed, w.V2.Terminated, w.V2.Observations}
}
func lifecycleV3Source(w *lifecycleV3Wire) (lifecycleRecord, error) {
	context, err := lifecycleV3SourceContext(w)
	if err != nil {
		return lifecycleRecord{}, err
	}
	return context.core.original, nil
}

func lifecycleV3SourceContext(w *lifecycleV3Wire) (*labRecoveryPlanValidationContext, error) {
	if w == nil {
		return nil, errLifecycleUnsafe
	}
	s := w.SourceV2
	if s.Schema != lifecycleSchemaV2 || s.ControlBytes == nil || len(s.ControlBytes) == 0 || len(s.ControlBytes) > maxLifecycleControlBytes || labConfigHash(s.ControlBytes) != s.ControlSHA256 {
		return nil, errLifecycleUnsafe
	}
	context, err := newLabRecoveryPlanValidationContext(s.ControlBytes)
	if err != nil {
		return nil, errLifecycleUnsafe
	}
	r := context.core.original
	if r.wire.RecordSHA256 != s.RecordSHA256 || r.wire.Revision != s.Revision ||
		r.wire.V2.Provisioning != w.Provisioning || r.wire.Active == nil || r.wire.Active.Phase != "UNKNOWN" || r.wire.Active.Attempt != 1 || r.wire.Active.Intent == nil ||
		w.Revision <= s.Revision || w.LastTrustedAt.Before(r.wire.LastTrustedAt) {
		return nil, errLifecycleUnsafe
	}
	return context, nil
}

// Validate a single ordinary epoch using unchanged per-entry validators. A v1
// projection here is an internal structural check, not an old wire or a token.
func validateLifecycleEpochLedger(l lifecycleEpochLedger, at time.Time, revision uint64) error {
	if l.Completed == nil || l.Terminated == nil || l.Observations == nil || l.Tombstones == nil || len(l.Completed)+len(l.Terminated) > maxLifecycleHistory || len(l.Observations) > maxLifecycleHistory || len(l.Tombstones) > maxLifecycleTombstones {
		return errLifecycleUnsafe
	}
	w := &lifecycleWire{Schema: lifecycleSchema, Boundary: lifecycleBoundary, Revision: revision, LastTrustedAt: at, LastFence: l.LastFence, Head: &l.Head, Owner: l.Owner, Tombstones: []lifecycleTombstone{}}
	// Validate both the anchor head and current head independently.
	w.Head = &l.Anchor.InitialHead
	w.RecordSHA256, _ = lifecycleRecordHash(*w)
	if validateLifecycleRecord(lifecycleRecord{wire: w}) != nil {
		return errLifecycleUnsafe
	}
	w.Head = &l.Head
	w.RecordSHA256, _ = lifecycleRecordHash(*w)
	if validateLifecycleRecord(lifecycleRecord{wire: w}) != nil {
		return errLifecycleUnsafe
	}
	if !lifecycleNonzeroHash(l.Anchor.SourceControlSHA256) || (l.Anchor.Kind != "LEGACY_V2" && l.Anchor.Kind != "RECOVERED_EPOCH") ||
		(l.Anchor.Kind == "LEGACY_V2" && (l.Anchor.RecoveryID != nil || l.Anchor.InitialHead.Generation != 1 || l.Anchor.InitialHead.PreviousHeadSHA256 != nil)) ||
		(l.Anchor.Kind == "RECOVERED_EPOCH" && (l.Anchor.RecoveryID == nil || !labRecoveryID.MatchString(*l.Anchor.RecoveryID) || l.Anchor.InitialHead.PreviousHeadSHA256 == nil)) {
		return errLifecycleUnsafe
	}
	ops, plans, intents := map[string]bool{}, map[string]bool{}, map[string]bool{}
	var lastRevision uint64
	for _, t := range l.Tombstones {
		if !planReference.MatchString(t.OperationID) || !lifecycleNonzeroHash(t.PlanSHA256) || ops[t.OperationID] || plans[t.PlanSHA256] || t.TerminalRevision <= lastRevision || t.TerminalRevision > revision || !lifecycleTerminal(t.Phase) {
			return errLifecycleUnsafe
		}
		ops[t.OperationID] = true
		plans[t.PlanSHA256] = true
		lastRevision = t.TerminalRevision
		if t.IntentSHA256 != nil {
			if !lifecycleNonzeroHash(*t.IntentSHA256) || intents[*t.IntentSHA256] {
				return errLifecycleUnsafe
			}
			intents[*t.IntentSHA256] = true
		}
		if t.Phase != lifecycleCompletedPhase {
			w.Tombstones = append(w.Tombstones, t)
		}
	}
	var previousAt time.Time
	lastRevision = 0
	var previousFence uint64
	for i, c := range l.Completed {
		if !lifecycleArchiveValid(c) || c.CommitRevision <= lastRevision || c.CommitRevision > revision || c.Owner.Fence > l.LastFence || c.Owner.Fence < previousFence || c.CommittedAt.After(at) || c.CommittedAt.Before(previousAt) ||
			(i == 0 && !reflect.DeepEqual(c.PreviousHead, l.Anchor.InitialHead)) || (i > 0 && !reflect.DeepEqual(c.PreviousHead, l.Completed[i-1].Head)) || !lifecycleEpochTombstone(l, c.Active, c.CommitRevision) {
			return errLifecycleUnsafe
		}
		lastRevision = c.CommitRevision
		previousAt = c.CommittedAt
		previousFence = c.Owner.Fence
	}
	if (len(l.Completed) == 0 && !reflect.DeepEqual(l.Head, l.Anchor.InitialHead)) || (len(l.Completed) > 0 && !reflect.DeepEqual(l.Head, l.Completed[len(l.Completed)-1].Head)) {
		return errLifecycleUnsafe
	}
	// Reuse the unchanged per-terminal archive checker without its v2 genesis rule.
	tw := &lifecycleWire{Head: &l.Head, Owner: l.Owner, LastFence: l.LastFence, Active: l.Active, Revision: revision, LastTrustedAt: at, Tombstones: l.Tombstones, V2: &lifecycleV2Wire{Completed: l.Completed, Terminated: l.Terminated}}
	if validateLifecycleTerminated(tw) != nil {
		return errLifecycleUnsafe
	}
	for _, t := range l.Tombstones {
		found := false
		for _, c := range l.Completed {
			if c.Active.Plan.OperationID == t.OperationID && c.Active.Plan.PlanSHA256 == t.PlanSHA256 && lifecycleEpochTombstone(l, c.Active, c.CommitRevision) {
				found = true
			}
		}
		for _, c := range l.Terminated {
			if c.Active.Plan.OperationID == t.OperationID && c.Active.Plan.PlanSHA256 == t.PlanSHA256 && lifecycleEpochTombstone(l, c.Active, c.CommitRevision) {
				found = true
			}
		}
		if !found {
			return errLifecycleUnsafe
		}
	}
	if l.Active != nil {
		a := *l.Active
		if a.Phase == lifecycleCompletedPhase {
			if len(l.Completed) == 0 || !reflect.DeepEqual(a, l.Completed[len(l.Completed)-1].Active) || (len(l.Terminated) > 0 && l.Terminated[len(l.Terminated)-1].CommitRevision > l.Completed[len(l.Completed)-1].CommitRevision) {
				return errLifecycleUnsafe
			}
		} else {
			if a.Result != nil {
				if !lifecycleResultSourceValid(lifecycleSchemaV2, &a) {
					return errLifecycleUnsafe
				}
				r := *a.Result
				r.Origin = ""
				r.ServiceGate = nil
				a.Result = &r
			}
			w.Active = &a
			w.RecordSHA256, _ = lifecycleRecordHash(*w)
			if validateLifecycleRecord(lifecycleRecord{wire: w}) != nil || a.Plan.CreatedAt.Before(l.Head.VerifiedAt) {
				return errLifecycleUnsafe
			}
		}
	}
	lastRevision = 0
	previousAt = time.Time{}
	for _, o := range l.Observations {
		a := l.Active
		if a == nil || a.Phase != "UNKNOWN" || a.Intent == nil || o.OperationID != a.Plan.OperationID || o.PlanSHA256 != a.Plan.PlanSHA256 || o.IntentSHA256 != a.Intent.IntentSHA256 ||
			!lifecycleReadbackValid(&o.Readback, lifecycleObservationConclusion, at) || o.Readback.ObservedAt.Before(a.Intent.ArmedAt) || (a.Result != nil && o.Readback.ObservedAt.Before(a.Result.ObservedAt)) ||
			o.CommitRevision <= lastRevision || o.CommitRevision > revision || o.Readback.ObservedAt.Before(previousAt) {
			return errLifecycleUnsafe
		}
		lastRevision = o.CommitRevision
		previousAt = o.Readback.ObservedAt
	}
	return nil
}
func lifecycleEpochTombstone(l lifecycleEpochLedger, a lifecycleActive, rev uint64) bool {
	for _, t := range l.Tombstones {
		if t.OperationID == a.Plan.OperationID && t.PlanSHA256 == a.Plan.PlanSHA256 && t.Phase == a.Phase && t.Attempt == a.Attempt && t.TerminalRevision == rev &&
			((a.Intent == nil && t.IntentSHA256 == nil) || (a.Intent != nil && t.IntentSHA256 != nil && a.Intent.IntentSHA256 == *t.IntentSHA256)) {
			return true
		}
	}
	return false
}

func validateLifecycleV3Record(r lifecycleV3Record) error {
	return validateLifecycleV3RecordScoped(r, newLifecycleV3DecodeScope())
}

func validateLifecycleV3RecordScoped(r lifecycleV3Record, scope *lifecycleV3DecodeScope) error {
	w := r.core
	if scope == nil || w == nil || w.Schema != lifecycleSchemaV3 || w.Boundary != lifecycleBoundary || w.Revision == 0 || !lifecycleTime(w.LastTrustedAt) || w.RetiredEpochs == nil || w.RecoveryHistory == nil || len(w.RetiredEpochs) > maxLifecycleHistory || len(w.RecoveryHistory) > maxLifecycleHistory {
		return errLifecycleUnsafe
	}
	h, err := lifecycleV3RecordHash(*w)
	if err != nil || h != w.RecordSHA256 || !lifecycleNonzeroHash(h) {
		return errLifecycleUnsafe
	}
	return validateLifecycleV3ContentsScoped(w, scope)
}

// All source, epoch, owner, candidate and complete-history checks are shared
// verbatim by strict external validation and the internal candidate sealer.
// This is not a proof or a caller assertion that any bytes were validated.
func validateLifecycleV3Contents(w *lifecycleV3Wire) error {
	return validateLifecycleV3ContentsScoped(w, newLifecycleV3DecodeScope())
}

func validateLifecycleV3ContentsScoped(w *lifecycleV3Wire, scope *lifecycleV3DecodeScope) error {
	if scope == nil || w == nil || scope.charge(len(w.RecoveryHistory)+len(w.RetiredEpochs)+1) != nil {
		return errLifecycleUnsafe
	}
	context, err := lifecycleV3SourceContext(w)
	if err != nil {
		return err
	}
	original := context.core.original
	legacy := lifecycleLegacyLedger(original, w.SourceV2.ControlBytes)
	if len(w.RetiredEpochs) == 0 {
		if !reflect.DeepEqual(w.Current, legacy) {
			return errLifecycleUnsafe
		}
	} else if !reflect.DeepEqual(w.RetiredEpochs[0].Ledger, legacy) {
		return errLifecycleUnsafe
	}
	if validateLifecycleEpochLedger(w.Current, w.LastTrustedAt, w.Revision) != nil {
		return errLifecycleUnsafe
	}
	owner := w.RecoveryOwner
	if owner == nil {
		if w.LastRecoveryFence != 0 || w.Recovery != nil {
			return errLifecycleUnsafe
		}
	} else if !lifecycleNonzeroHash(owner.OwnerNonce) || owner.Fence == 0 || owner.Fence != w.LastRecoveryFence || !lifecycleTime(owner.AcquiredAt) || !lifecycleTime(owner.RenewedAt) || !lifecycleTime(owner.ExpiresAt) || owner.RenewedAt.Before(owner.AcquiredAt) || owner.RenewedAt.After(w.LastTrustedAt) || !owner.ExpiresAt.After(owner.RenewedAt) {
		return errLifecycleUnsafe
	}
	recoveryIDs := map[string]bool{}
	var histRevision uint64
	var histAt time.Time
	for _, a := range w.RecoveryHistory {
		planContext, contextErr := lifecycleRecoveryPlanContextScoped(w, a.Plan, scope)
		if recoveryIDs[a.Plan.RecoveryID] || contextErr != nil || validateLifecycleRecoveryTxn(a, planContext, w.LastTrustedAt, w.Revision) != nil ||
			(a.Execution != nil && (a.Phase != "COMPLETED" || a.Execution.Schema != lifecycleRecoveryCompletedExecutionSchema || validateLifecycleRecoveryExecutionScoped(w, a, scope) != nil)) ||
			(a.Phase != "REVOKED_UNSTARTED" && a.Phase != "COMPLETED") || a.UpdatedAt.Before(histAt) {
			return errLifecycleUnsafe
		}
		recoveryIDs[a.Plan.RecoveryID] = true
		histAt = a.UpdatedAt
	}
	if w.Recovery != nil {
		a := *w.Recovery
		planContext, contextErr := lifecycleRecoveryPlanContextScoped(w, a.Plan, scope)
		if contextErr != nil || validateLifecycleRecoveryTxn(a, planContext, w.LastTrustedAt, w.Revision) != nil {
			return errLifecycleUnsafe
		}
		if validateLifecycleRecoveryExecutionScoped(w, a, scope) != nil {
			return errLifecycleUnsafe
		}
		if recoveryIDs[a.Plan.RecoveryID] {
			if len(w.RecoveryHistory) == 0 || !reflect.DeepEqual(a, w.RecoveryHistory[len(w.RecoveryHistory)-1]) {
				return errLifecycleUnsafe
			}
		} else if a.Phase == "COMPLETED" || a.Phase == "REVOKED_UNSTARTED" {
			return errLifecycleUnsafe
		}
		if a.StopIntent != nil && a.Phase != "COMPLETED" && a.StopIntent.OwnerFence != w.LastRecoveryFence {
			return errLifecycleUnsafe
		}
	}
	var previousRetiredAt time.Time
	for i, e := range w.RetiredEpochs {
		digest, _ := lifecycleHash(e.Ledger)
		if digest != e.LedgerSHA256 || e.CommitRevision <= histRevision || e.CommitRevision > w.Revision || !lifecycleTime(e.RetiredAt) || e.RetiredAt.Before(previousRetiredAt) || e.RetiredAt.After(w.LastTrustedAt) || validateLifecycleEpochLedger(e.Ledger, e.RetiredAt, e.CommitRevision) != nil {
			return errLifecycleUnsafe
		}
		var completion *lifecycleRecoveryCompletion
		for j := range w.RecoveryHistory {
			a := &w.RecoveryHistory[j]
			if a.Plan.RecoveryID == e.RecoveryID && a.Phase == "COMPLETED" {
				completion = a.Completion
			}
		}
		if completion == nil || completion.CommitRevision != e.CommitRevision || !completion.CommittedAt.Equal(e.RetiredAt) || !reflect.DeepEqual(completion.PreviousHead, e.Ledger.Head) {
			return errLifecycleUnsafe
		}
		next := w.Current.Anchor
		if i+1 < len(w.RetiredEpochs) {
			next = w.RetiredEpochs[i+1].Ledger.Anchor
		}
		if next.Kind != "RECOVERED_EPOCH" || next.RecoveryID == nil || *next.RecoveryID != e.RecoveryID || !reflect.DeepEqual(next.InitialHead, completion.Head) || next.SourceControlSHA256 != w.SourceV2.ControlSHA256 {
			return errLifecycleUnsafe
		}
		histRevision = e.CommitRevision
		previousRetiredAt = e.RetiredAt
	}
	completedRecoveries := 0
	for _, a := range w.RecoveryHistory {
		if a.Phase == "COMPLETED" {
			completedRecoveries++
		}
	}
	if completedRecoveries != len(w.RetiredEpochs) {
		return errLifecycleUnsafe
	}
	// Duplicated source/first retired state is exact provenance, not a second
	// operation. Across physical ledgers, old operations may never be reused.
	ledgers := make([]lifecycleEpochLedger, 0, len(w.RetiredEpochs)+1)
	for _, e := range w.RetiredEpochs {
		ledgers = append(ledgers, e.Ledger)
	}
	ledgers = append(ledgers, w.Current)
	ops, plans, intents := map[string]bool{}, map[string]bool{}, map[string]bool{}
	historyCount, observationCount := len(w.RecoveryHistory), 0
	if w.Recovery != nil && !recoveryIDs[w.Recovery.Plan.RecoveryID] {
		historyCount++
	}
	for _, l := range ledgers {
		historyCount += len(l.Completed) + len(l.Terminated)
		observationCount += len(l.Observations)
		local := map[string]bool{}
		for _, t := range l.Tombstones {
			if ops[t.OperationID] || plans[t.PlanSHA256] {
				return errLifecycleUnsafe
			}
			ops[t.OperationID] = true
			plans[t.PlanSHA256] = true
			local[t.OperationID] = true
			if t.IntentSHA256 != nil {
				if intents[*t.IntentSHA256] {
					return errLifecycleUnsafe
				}
				intents[*t.IntentSHA256] = true
			}
		}
		if a := l.Active; a != nil && !local[a.Plan.OperationID] {
			if ops[a.Plan.OperationID] || plans[a.Plan.PlanSHA256] {
				return errLifecycleUnsafe
			}
			ops[a.Plan.OperationID] = true
			plans[a.Plan.PlanSHA256] = true
			if a.Intent != nil {
				if intents[a.Intent.IntentSHA256] {
					return errLifecycleUnsafe
				}
				intents[a.Intent.IntentSHA256] = true
			}
		}
	}
	for _, a := range w.RecoveryHistory {
		observationCount += len(a.FailedQuiescence)
	}
	if w.Recovery != nil && !recoveryIDs[w.Recovery.Plan.RecoveryID] {
		observationCount += len(w.Recovery.FailedQuiescence)
	}
	if historyCount > maxLifecycleHistory || observationCount > maxLifecycleHistory {
		return errLifecycleUnsafe
	}
	return nil
}
