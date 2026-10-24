package mihomodeploy

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync"
	"time"

	"chengwang/internal/adapter/mihomo"
	"chengwang/internal/authz"
)

const lifecycleSchema = "chengwang.mihomo-lifecycle-record/v1"
const lifecycleBoundary = "STRUCTURAL_DURABLE_LAB_RECORD_NOT_AUTHORIZATION"
const lifecycleHeadSchema = "chengwang.mihomo-lifecycle-head/v1"
const lifecycleIntentSchema = "chengwang.mihomo-reload-intent/v1"
const maxLifecycleTombstones = 256
const lifecycleDebug = "private structural Mihomo lifecycle record; not authorization"

// These types are private persistence DTOs, not caller-authorized commands.
// Their containing record is opaque to ordinary JSON/debugging. The only raw
// encoder is encodeLifecycleRecord, for the already-private disk backend.
type lifecycleHead struct {
	Schema string `json:"schema"`
	DeviceRef string `json:"deviceRef"`
	Scope authz.ResourceScope `json:"scope"`
	Generation uint64 `json:"generation"`
	Artifact ArtifactDescriptor `json:"artifact"`
	KernelSHA256 string `json:"kernelSHA256"`
	PID int `json:"pid"`
	StartTicks uint64 `json:"startTicks"`
	NetNSInode uint64 `json:"netNSInode"`
	ControllerPort uint16 `json:"controllerPort"`
	MixedPort uint16 `json:"mixedPort"`
	VerificationSHA256 string `json:"verificationSHA256"`
	VerifiedAt time.Time `json:"verifiedAt"`
	PreviousHeadSHA256 *string `json:"previousHeadSHA256"`
	HeadSHA256 string `json:"headSHA256"`
}
type lifecycleOwner struct {
	OwnerNonce string `json:"ownerNonce"`
	Fence uint64 `json:"fence"`
	AcquiredAt time.Time `json:"acquiredAt"`
	RenewedAt time.Time `json:"renewedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}
type lifecycleApproval struct {
	Material ApprovalMaterial `json:"material"`
	ApprovalID string `json:"approvalID"`
	AuthoritySnapshotRef *string `json:"authoritySnapshotRef"`
}
type lifecycleRevocation struct {
	Revision uint64 `json:"revision"`
	At time.Time `json:"at"`
	Reason string `json:"reason"`
	ActorRef string `json:"actorRef"`
}
type lifecycleIntent struct {
	Schema string `json:"schema"`
	OperationID string `json:"operationId"`
	PlanSHA256 string `json:"planSHA256"`
	ExpectedHeadSHA256 string `json:"expectedHeadSHA256"`
	CandidateRecordSHA256 string `json:"candidateRecordSHA256"`
	BackupSHA256 string `json:"backupSHA256"`
	OwnerFence uint64 `json:"ownerFence"`
	ArmedAt time.Time `json:"armedAt"`
	IntentSHA256 string `json:"intentSHA256"`
}
type lifecycleResult struct {
	Reload mihomo.ReloadResult `json:"reload"`
	ObservedAt time.Time `json:"observedAt"`
}
type lifecycleReadback struct {
	Conclusion string `json:"conclusion"`
	EvidenceSHA256 string `json:"evidenceSHA256"`
	ObservedAt time.Time `json:"observedAt"`
}
type lifecycleActive struct {
	Plan PlanDescriptor `json:"plan"`
	Phase string `json:"phase"`
	Approval *lifecycleApproval `json:"approval"`
	Revocation *lifecycleRevocation `json:"revocation"`
	Attempt int `json:"attempt"`
	Intent *lifecycleIntent `json:"intent"`
	Result *lifecycleResult `json:"result"`
	Readback *lifecycleReadback `json:"readback"`
	AuditProjection []string `json:"auditProjection"`
	Recovery *json.RawMessage `json:"recovery"`
}
type lifecycleTombstone struct {
	OperationID string `json:"operationId"`
	PlanSHA256 string `json:"planSHA256"`
	Attempt int `json:"attempt"`
	IntentSHA256 *string `json:"intentSHA256"`
	Phase string `json:"phase"`
	TerminalRevision uint64 `json:"terminalRevision"`
}
type lifecycleWire struct {
	Schema string `json:"schema"`
	Boundary string `json:"boundary"`
	Revision uint64 `json:"revision"`
	RecordSHA256 string `json:"recordSHA256"`
	LastTrustedAt time.Time `json:"lastTrustedAt"`
	LastFence uint64 `json:"lastFence"`
	Head *lifecycleHead `json:"head"`
	Owner *lifecycleOwner `json:"owner"`
	Active *lifecycleActive `json:"active"`
	Tombstones []lifecycleTombstone `json:"tombstones"`
}
// One opaque pointer is intentional: fmt's unsupported-verb error path can
// skip Formatter methods and reflect a value copy. It must see at most an
// address, never inline persistence fields or a reversible raw byte slice.
type lifecycleRecord struct { wire *lifecycleWire }

func (lifecycleRecord) String() string { return lifecycleDebug }
func (lifecycleRecord) GoString() string { return lifecycleDebug }
func (lifecycleRecord) MarshalJSON() ([]byte, error) { return []byte(`{"scope":"STRUCTURAL_RECORD_NOT_AUTHORIZATION"}`), nil }
func (lifecycleRecord) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, lifecycleDebug) }

func lifecycleHash(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil { return "", errLifecycleUnsafe }
	return labConfigHash(raw), nil
}
func lifecycleNonzeroHash(s string) bool { return planHash.MatchString(s) && s != strings.Repeat("0", 64) }
func lifecycleTime(t time.Time) bool { return planTime(t) && t.Location() == time.UTC }

// The binding structs deliberately specify field order and omit only their own
// digest. No map encoding, float64 conversion, or mutable external DTO is used.
func lifecycleHeadHash(h lifecycleHead) (string, error) {
	return lifecycleHash(struct {
		Schema string `json:"schema"`; DeviceRef string `json:"deviceRef"`; Scope authz.ResourceScope `json:"scope"`
		Generation uint64 `json:"generation"`; Artifact ArtifactDescriptor `json:"artifact"`; KernelSHA256 string `json:"kernelSHA256"`
		PID int `json:"pid"`; StartTicks uint64 `json:"startTicks"`; NetNSInode uint64 `json:"netNSInode"`
		ControllerPort uint16 `json:"controllerPort"`; MixedPort uint16 `json:"mixedPort"`; VerificationSHA256 string `json:"verificationSHA256"`
		VerifiedAt time.Time `json:"verifiedAt"`; PreviousHeadSHA256 *string `json:"previousHeadSHA256"`
	}{h.Schema,h.DeviceRef,h.Scope,h.Generation,h.Artifact,h.KernelSHA256,h.PID,h.StartTicks,h.NetNSInode,h.ControllerPort,h.MixedPort,h.VerificationSHA256,h.VerifiedAt,h.PreviousHeadSHA256})
}
func lifecycleIntentHash(v lifecycleIntent) (string, error) {
	return lifecycleHash(struct {
		Schema string `json:"schema"`; OperationID string `json:"operationId"`; PlanSHA256 string `json:"planSHA256"`
		ExpectedHeadSHA256 string `json:"expectedHeadSHA256"`; CandidateRecordSHA256 string `json:"candidateRecordSHA256"`
		BackupSHA256 string `json:"backupSHA256"`; OwnerFence uint64 `json:"ownerFence"`; ArmedAt time.Time `json:"armedAt"`
	}{v.Schema,v.OperationID,v.PlanSHA256,v.ExpectedHeadSHA256,v.CandidateRecordSHA256,v.BackupSHA256,v.OwnerFence,v.ArmedAt})
}
func lifecycleRecordHash(w lifecycleWire) (string, error) {
	return lifecycleHash(struct {
		Schema string `json:"schema"`; Boundary string `json:"boundary"`; Revision uint64 `json:"revision"`
		LastTrustedAt time.Time `json:"lastTrustedAt"`; LastFence uint64 `json:"lastFence"`; Head *lifecycleHead `json:"head"`
		Owner *lifecycleOwner `json:"owner"`; Active *lifecycleActive `json:"active"`; Tombstones []lifecycleTombstone `json:"tombstones"`
	}{w.Schema,w.Boundary,w.Revision,w.LastTrustedAt,w.LastFence,w.Head,w.Owner,w.Active,w.Tombstones})
}

// Inspect tokens before typed decoding: retain exact integers, reject duplicate
// keys at every level and bound depth without retaining arbitrary input text.
func lifecycleTokens(d *json.Decoder, depth int) error {
	if depth > 24 { return errLifecycleUnsafe }
	t, err := d.Token(); if err != nil { return errLifecycleUnsafe }
	delim, ok := t.(json.Delim); if !ok { return nil }
	switch delim {
	case '{':
		keys := make(map[string]bool)
		for d.More() {
			k, err := d.Token(); if err != nil { return errLifecycleUnsafe }
			s, ok := k.(string); if !ok || keys[s] { return errLifecycleUnsafe }; keys[s] = true
			if err := lifecycleTokens(d, depth+1); err != nil { return err }
		}
		end, err := d.Token(); if err != nil || end != json.Delim('}') { return errLifecycleUnsafe }
	case '[':
		for d.More() { if err := lifecycleTokens(d, depth+1); err != nil { return err } }
		end, err := d.Token(); if err != nil || end != json.Delim(']') { return errLifecycleUnsafe }
	default: return errLifecycleUnsafe
	}
	return nil
}
func decodeLifecycleRecord(raw []byte) (lifecycleRecord, error) {
	if len(raw) == 0 || len(raw) > maxLifecycleControlBytes { return lifecycleRecord{}, errLifecycleUnsafe }
	d := json.NewDecoder(bytes.NewReader(raw)); d.UseNumber()
	if lifecycleTokens(d, 0) != nil { return lifecycleRecord{}, errLifecycleUnsafe }
	if _, err := d.Token(); err != io.EOF { return lifecycleRecord{}, errLifecycleUnsafe }
	var w lifecycleWire
	d = json.NewDecoder(bytes.NewReader(raw)); d.DisallowUnknownFields()
	if d.Decode(&w) != nil { return lifecycleRecord{}, errLifecycleUnsafe }
	r := lifecycleRecord{wire:&w}
	canonical, err := encodeLifecycleRecord(r)
	if err != nil || !bytes.Equal(canonical, raw) { return lifecycleRecord{}, errLifecycleUnsafe }
	return r, nil
}
func encodeLifecycleRecord(r lifecycleRecord) ([]byte, error) {
	if err := validateLifecycleRecord(r); err != nil { return nil, err }
	raw, err := json.Marshal(r.wire)
	if err != nil || len(raw) > maxLifecycleControlBytes { return nil, errLifecycleUnsafe }
	return raw, nil
}
func lifecyclePlan(d PlanDescriptor) (Plan, error) {
	if !lifecycleArtifactDescriptorValid(d.Artifact)||!lifecycleArtifactDescriptorValid(d.Backup.Artifact){return Plan{},errLifecycleUnsafe}
	p, err := NewPlan(PlanSpec{OperationID:d.OperationID, DeclaredInitiatorRef:d.DeclaredInitiatorRef,
		Target:d.Target, Artifact:d.Artifact, Backup:d.Backup, ExpiresAt:d.ExpiresAt}, d.CreatedAt)
	if err != nil || !reflect.DeepEqual(p.Descriptor(), d) || !lifecycleTime(d.CreatedAt) || !lifecycleTime(d.ExpiresAt) {
		return Plan{}, errLifecycleUnsafe
	}
	return p, nil
}
func lifecycleArtifactDescriptorValid(d ArtifactDescriptor) bool {
	// The older descriptor validator intentionally accepts zero-length slices;
	// this exact lifecycle wire additionally requires [] rather than JSON null.
	return d.Config.Capabilities!=nil && d.Config.Requirements!=nil && d.Config.Blockers!=nil && validateArtifactDescriptor(d)==nil
}
func lifecycleHeadTarget(h lifecycleHead) TargetBinding {
	return TargetBinding{DeviceRef:h.DeviceRef, Scope:h.Scope, Generation:h.Generation, HeadSHA256:h.HeadSHA256,
		KernelSHA256:h.KernelSHA256, PID:h.PID, StartTicks:h.StartTicks, NetNSInode:h.NetNSInode,
		ControllerPort:h.ControllerPort, MixedPort:h.MixedPort}
}
func lifecycleTerminal(phase string) bool { return phase == "REVOKED" || phase == "UNSENT_REJECTED" }
func lifecyclePrearm(a *lifecycleActive) bool {
	return a!=nil && a.Attempt==0 && a.Intent==nil && a.Result==nil &&
		(a.Phase=="PLANNED"||a.Phase=="APPROVED"||a.Phase=="PREPARED")
}
func lifecyclePhaseTransition(from,to string) bool {
	switch from {
	case "PLANNED":return to==from||to=="APPROVED"||to=="REVOKED"
	case "APPROVED":return to==from||to=="PREPARED"||to=="REVOKED"
	case "PREPARED":return to==from||to=="DISPATCH_ARMED"||to=="REVOKED"
	case "DISPATCH_ARMED":return to==from||to=="ACKNOWLEDGED"||to=="UNSENT_REJECTED"||to=="RESPONSE_REJECTED"||to=="UNKNOWN"
	case "ACKNOWLEDGED":return to==from||to=="UNKNOWN"
	case "UNKNOWN","MANUAL_REQUIRED","RESPONSE_REJECTED","REVOKED","UNSENT_REJECTED":return to==from
	default:return false
	}
}
func lifecycleResultValid(r mihomo.ReloadResult) bool {
	switch r.State {
	case mihomo.ReloadAcknowledged: return r.Dispatched && r.StatusCode == 204
	case mihomo.ReloadRejected: return (!r.Dispatched && r.StatusCode == 0) || (r.Dispatched && r.StatusCode >= 400 && r.StatusCode <= 499)
	case mihomo.ReloadUnknown: return r.Dispatched && (r.StatusCode == 0 || r.StatusCode >= 100 && r.StatusCode <= 599)
	default: return false
	}
}
var lifecycleAuditKeys = map[string]bool{"PLANNED":true,"APPROVAL_RECORDED":true,"PREPARED":true,"INTENT_ARMED":true,"RESULT_RECORDED":true,"REVOCATION_RECORDED":true,"REOPENED_UNKNOWN":true}

func validateLifecycleRecord(r lifecycleRecord) error {
	w := r.wire
	if w==nil { return errLifecycleUnsafe }
	if w.Schema != lifecycleSchema || w.Boundary != lifecycleBoundary || w.Revision == 0 || !lifecycleTime(w.LastTrustedAt) ||
		w.Tombstones == nil || len(w.Tombstones) > maxLifecycleTombstones { return errLifecycleUnsafe }
	digest, err := lifecycleRecordHash(*w); if err != nil || !lifecycleNonzeroHash(w.RecordSHA256) || digest != w.RecordSHA256 { return errLifecycleUnsafe }
	if w.Head != nil {
		h := w.Head; hash, err := lifecycleHeadHash(*h)
		if h.Schema != lifecycleHeadSchema || validateTargetBinding(lifecycleHeadTarget(*h)) != nil ||
			!lifecycleArtifactDescriptorValid(h.Artifact) || !h.Artifact.Config.Admissible ||
			h.Artifact.ControllerPort != h.ControllerPort || h.Artifact.MixedPort != h.MixedPort ||
			!lifecycleNonzeroHash(h.VerificationSHA256) || !lifecycleTime(h.VerifiedAt) || h.VerifiedAt.After(w.LastTrustedAt) ||
			(h.PreviousHeadSHA256 != nil && !lifecycleNonzeroHash(*h.PreviousHeadSHA256)) || err != nil || hash != h.HeadSHA256 { return errLifecycleUnsafe }
	}
	if w.Owner != nil {
		o := w.Owner
		if !lifecycleNonzeroHash(o.OwnerNonce) || o.Fence == 0 || o.Fence != w.LastFence || !lifecycleTime(o.AcquiredAt) || !lifecycleTime(o.RenewedAt) || !lifecycleTime(o.ExpiresAt) ||
			o.RenewedAt.Before(o.AcquiredAt) || o.RenewedAt.After(w.LastTrustedAt) || !o.ExpiresAt.After(o.RenewedAt) { return errLifecycleUnsafe }
	} else if w.LastFence != 0 { return errLifecycleUnsafe }
	ops, plans, intents := map[string]bool{}, map[string]bool{}, map[string]bool{}
	var previous uint64
	for _, t := range w.Tombstones {
		if !planReference.MatchString(t.OperationID) || !lifecycleNonzeroHash(t.PlanSHA256) || t.TerminalRevision <= previous || t.TerminalRevision > w.Revision ||
			!lifecycleTerminal(t.Phase) || ops[t.OperationID] || plans[t.PlanSHA256] { return errLifecycleUnsafe }
		if (t.Phase=="REVOKED" && (t.Attempt!=0 || t.IntentSHA256!=nil)) ||
			(t.Phase=="UNSENT_REJECTED" && (t.Attempt!=1 || t.IntentSHA256==nil || !lifecycleNonzeroHash(*t.IntentSHA256))) { return errLifecycleUnsafe }
		if t.IntentSHA256!=nil { if intents[*t.IntentSHA256] { return errLifecycleUnsafe }; intents[*t.IntentSHA256]=true }
		previous = t.TerminalRevision; ops[t.OperationID] = true; plans[t.PlanSHA256] = true
	}
	if w.Active == nil { return nil }
	a := w.Active
	if w.Head == nil || w.Owner == nil || a.Readback != nil || a.Recovery != nil || a.AuditProjection == nil || len(a.AuditProjection) > len(lifecycleAuditKeys) { return errLifecycleUnsafe }
	p, err := lifecyclePlan(a.Plan)
	if err != nil || a.Plan.Target != lifecycleHeadTarget(*w.Head) || !reflect.DeepEqual(a.Plan.Backup.Artifact, w.Head.Artifact) || a.Plan.CreatedAt.After(w.LastTrustedAt) { return errLifecycleUnsafe }
	seen := map[string]bool{}
	for _, key := range a.AuditProjection { if !lifecycleAuditKeys[key] || seen[key] { return errLifecycleUnsafe }; seen[key] = true }
	if a.Approval != nil {
		v := a.Approval
		if v.ApprovalID!=lifecycleApprovalID(a.Plan) || v.AuthoritySnapshotRef != nil || !lifecycleTime(v.Material.IssuedAt) || !lifecycleTime(v.Material.ExpiresAt) ||
			v.Material.IssuedAt.After(w.LastTrustedAt) || ValidateApprovalMaterial(p,v.Material,v.Material.IssuedAt) != nil { return errLifecycleUnsafe }
	}
	if a.Revocation != nil {
		v := a.Revocation
		if v.Revision == 0 || v.Revision > w.Revision || !lifecycleTime(v.At) || v.At.Before(a.Plan.CreatedAt) || v.At.After(w.LastTrustedAt) || !planReference.MatchString(v.ActorRef) ||
			(v.Reason != "EXPLICIT_REVOKED" && v.Reason != "AUTHORITY_CHANGED" && v.Reason != "EXPIRED") { return errLifecycleUnsafe }
	}
	if a.Attempt != 0 && a.Attempt != 1 { return errLifecycleUnsafe }
	if a.Attempt == 0 {
		if a.Intent != nil || a.Result != nil { return errLifecycleUnsafe }
		switch a.Phase {
		case "PLANNED":
		case "APPROVED", "PREPARED": if a.Approval == nil { return errLifecycleUnsafe }
		case "REVOKED": if a.Revocation == nil { return errLifecycleUnsafe }
		default: return errLifecycleUnsafe
		}
		if a.Revocation != nil && a.Phase != "REVOKED" { return errLifecycleUnsafe }
	} else {
		i := a.Intent
		if i == nil || a.Approval == nil { return errLifecycleUnsafe }
		hash, err := lifecycleIntentHash(*i)
		if i.Schema != lifecycleIntentSchema || i.OperationID != a.Plan.OperationID || i.PlanSHA256 != a.Plan.PlanSHA256 ||
			i.ExpectedHeadSHA256 != w.Head.HeadSHA256 || i.CandidateRecordSHA256 != a.Plan.Artifact.RecordSHA256 ||
			i.BackupSHA256 != a.Plan.Backup.BackupSHA256 || i.OwnerFence != w.Owner.Fence || !lifecycleTime(i.ArmedAt) ||
			i.ArmedAt.Before(a.Plan.CreatedAt) || i.ArmedAt.Before(a.Approval.Material.IssuedAt) || !i.ArmedAt.Before(a.Plan.ExpiresAt) ||
			!i.ArmedAt.Before(a.Approval.Material.ExpiresAt) || i.ArmedAt.After(w.LastTrustedAt) || err != nil || hash != i.IntentSHA256 { return errLifecycleUnsafe }
		if a.Result != nil && (!lifecycleResultValid(a.Result.Reload) || !lifecycleTime(a.Result.ObservedAt) || a.Result.ObservedAt.Before(i.ArmedAt) || a.Result.ObservedAt.After(w.LastTrustedAt)) { return errLifecycleUnsafe }
		switch a.Phase {
		case "DISPATCH_ARMED": if a.Result != nil { return errLifecycleUnsafe }
		case "UNKNOWN", "MANUAL_REQUIRED":
		case "ACKNOWLEDGED": if a.Result == nil || a.Result.Reload.State != mihomo.ReloadAcknowledged { return errLifecycleUnsafe }
		case "UNSENT_REJECTED": if a.Result == nil || a.Result.Reload.State != mihomo.ReloadRejected || a.Result.Reload.Dispatched { return errLifecycleUnsafe }
		case "RESPONSE_REJECTED": if a.Result == nil || a.Result.Reload.State != mihomo.ReloadRejected || !a.Result.Reload.Dispatched { return errLifecycleUnsafe }
		default: return errLifecycleUnsafe
		}
	}
	// Current collector-free version can only terminalize pre-dispatch revoke
	// or a recorded unsent rejection. Sent/unknown operations remain blocking.
	matched := false
	for _, t := range w.Tombstones {
		if t.OperationID == a.Plan.OperationID || t.PlanSHA256 == a.Plan.PlanSHA256 {
			if t.OperationID != a.Plan.OperationID || t.PlanSHA256 != a.Plan.PlanSHA256 || t.Attempt != a.Attempt || t.Phase != a.Phase ||
				(a.Intent!=nil && (t.IntentSHA256==nil || *t.IntentSHA256!=a.Intent.IntentSHA256)) { return errLifecycleUnsafe }
			matched = true
		}
	}
	if lifecycleTerminal(a.Phase) != matched { return errLifecycleUnsafe }
	if a.Intent!=nil && intents[a.Intent.IntentSHA256] && !matched { return errLifecycleUnsafe }
	return nil
}

// lifecycleOwnerToken is a process-local possession check, NOT authentication.
// It is deliberately not reconstructible from owner JSON or opaque references.
type lifecycleOwnerCore struct { store *lifecycleStore; nonce string; fence uint64 }
type lifecycleOwnerToken struct { *lifecycleOwnerCore }
func (lifecycleOwnerToken) String() string { return lifecycleDebug }
func (lifecycleOwnerToken) GoString() string { return lifecycleDebug }
func (lifecycleOwnerToken) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s,lifecycleDebug) }
func (lifecycleOwnerToken) MarshalJSON() ([]byte,error) { return []byte(`{"scope":"IN_MEMORY_OWNER_NOT_AUTHORIZATION"}`),nil }
type lifecycleStoreCore struct {
	mu *sync.Mutex
	disk lifecycleDisk
	record lifecycleRecord
	raw []byte
	live *lifecycleOwnerToken
	closed, poisoned bool
}
type lifecycleStore struct { *lifecycleStoreCore }
func (lifecycleStore) String() string { return lifecycleDebug }
func (lifecycleStore) GoString() string { return lifecycleDebug }
func (lifecycleStore) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s,lifecycleDebug) }
func (lifecycleStore) MarshalJSON() ([]byte,error) { return []byte(`{"scope":"PRIVATE_LIFECYCLE_STORE_NOT_AUTHORIZATION"}`),nil }

func openLifecycleStore(d lifecycleDisk) (*lifecycleStore,error) {
	if d == nil { return nil,errLifecycleUnsafe }
	v := reflect.ValueOf(d)
	switch v.Kind() { case reflect.Pointer,reflect.Map,reflect.Slice,reflect.Func,reflect.Chan,reflect.Interface:
		if v.IsNil() { return nil,errLifecycleUnsafe }
	}
	if err := d.verify(); err != nil { return nil,err }
	raw, exists, err := d.readControl()
	if err != nil { return nil,err }; if !exists { return nil,errLifecycleUnsafe }
	r, err := decodeLifecycleRecord(raw); if err != nil { return nil,err }
	s := &lifecycleStore{lifecycleStoreCore:&lifecycleStoreCore{mu:&sync.Mutex{},disk:d,record:r,raw:bytes.Clone(raw)}}
	if r.wire.Active != nil && (r.wire.Active.Phase == "DISPATCH_ARMED" || r.wire.Active.Phase == "ACKNOWLEDGED") {
		next, err := s.copyRecord(); if err != nil { return nil,err }
		next.wire.Active.Phase = "UNKNOWN"; lifecycleAppendAudit(next.wire.Active,"REOPENED_UNKNOWN")
		if err := s.commit(next,r.wire.LastTrustedAt); err != nil { return nil,err }
	}
	return s,nil
}
func (s *lifecycleStore) copyRecord() (lifecycleRecord,error) {
	if s==nil||s.lifecycleStoreCore==nil{return lifecycleRecord{},errLifecycleUnsafe}
	if s.closed{return lifecycleRecord{},errLifecycleUnsafe};if s.poisoned{return lifecycleRecord{},errLifecyclePoisoned}
	return decodeLifecycleRecord(s.raw)
}
func (s *lifecycleStore) verify() error {
	if s == nil || s.lifecycleStoreCore==nil || s.mu==nil || s.record.wire==nil || s.closed || s.disk == nil { return errLifecycleUnsafe }
	if s.poisoned { return errLifecyclePoisoned }
	if err := s.disk.verify(); err != nil { s.poisoned = true; return err }
	raw, exists, err := s.disk.readControl()
	if err != nil || !exists || !bytes.Equal(raw,s.raw) { s.poisoned = true; return errLifecycleUnsafe }
	r, err := decodeLifecycleRecord(raw)
	if err != nil || r.wire.Revision != s.record.wire.Revision || r.wire.RecordSHA256 != s.record.wire.RecordSHA256 { s.poisoned = true; return errLifecycleUnsafe }
	return nil
}
func (s *lifecycleStore) commit(next lifecycleRecord, now time.Time) error {
	if err := s.verify(); err != nil { return err }
	if err:=s.trustedNow(now);err!=nil{return err}
	if next.wire==nil || s.record.wire.Revision == ^uint64(0) { return errLifecycleUnsafe }
	old:=s.record.wire
	// No current source can bootstrap/replace a running head. Terminal head
	// advancement requires a future authenticated collector and codec evolution.
	if !reflect.DeepEqual(next.wire.Head,old.Head) || len(next.wire.Tombstones)<len(old.Tombstones) ||
		!reflect.DeepEqual(next.wire.Tombstones[:len(old.Tombstones)],old.Tombstones) { return errLifecycleUnsafe }
	if next.wire.LastFence!=old.LastFence && (old.LastFence==^uint64(0)||next.wire.LastFence!=old.LastFence+1) { return errLifecycleUnsafe }
	if next.wire.LastFence==old.LastFence {
		if (old.Owner==nil)!=(next.wire.Owner==nil){return errLifecycleUnsafe}
		if old.Owner!=nil && (next.wire.Owner.OwnerNonce!=old.Owner.OwnerNonce||next.wire.Owner.Fence!=old.Owner.Fence||
			!next.wire.Owner.AcquiredAt.Equal(old.Owner.AcquiredAt)||next.wire.Owner.RenewedAt.Before(old.Owner.RenewedAt)||next.wire.Owner.ExpiresAt.Before(old.Owner.ExpiresAt)){return errLifecycleUnsafe}
	} else if next.wire.Owner==nil || (old.Owner!=nil&&now.Before(old.Owner.ExpiresAt)) ||
		!next.wire.Owner.AcquiredAt.Equal(now)||!next.wire.Owner.RenewedAt.Equal(now) { return errLifecycleUnsafe }
	if old.Active!=nil && next.wire.Active!=nil && old.Active.Plan.PlanSHA256==next.wire.Active.Plan.PlanSHA256 {
		a,b:=old.Active,next.wire.Active
		if !lifecyclePhaseTransition(a.Phase,b.Phase)||!reflect.DeepEqual(a.Plan,b.Plan)||b.Attempt<a.Attempt||(a.Intent!=nil&&!reflect.DeepEqual(a.Intent,b.Intent))||
			(a.Result!=nil&&!reflect.DeepEqual(a.Result,b.Result))||(a.Approval!=nil&&!reflect.DeepEqual(a.Approval,b.Approval))||
			len(b.AuditProjection)<len(a.AuditProjection)||!reflect.DeepEqual(b.AuditProjection[:len(a.AuditProjection)],a.AuditProjection){return errLifecycleUnsafe}
		if a.Revocation!=nil && (b.Revocation==nil||b.Revocation.Revision<a.Revocation.Revision||
			(b.Revocation.Revision==a.Revocation.Revision&&!reflect.DeepEqual(a.Revocation,b.Revocation))){return errLifecycleUnsafe}
	} else if old.Active!=nil && !lifecycleTerminal(old.Active.Phase) { return errLifecycleUnsafe }
	if next.wire.Active!=nil && (old.Active==nil||old.Active.Plan.PlanSHA256!=next.wire.Active.Plan.PlanSHA256) {
		for _,t:=range old.Tombstones{if t.OperationID==next.wire.Active.Plan.OperationID||t.PlanSHA256==next.wire.Active.Plan.PlanSHA256{return errLifecycleUnsafe}}
	}
	next.wire.Revision = s.record.wire.Revision+1; next.wire.LastTrustedAt = now
	hash, err := lifecycleRecordHash(*next.wire); if err != nil { return err }; next.wire.RecordSHA256=hash
	raw, err := encodeLifecycleRecord(next); if err != nil { return err }
	state, err := s.disk.replaceControl(raw)
	if state == lifecycleUnknown || (state!=lifecycleNotCommitted && state!=lifecycleCommitted) { s.poisoned=true; return errLifecycleCommitUnknown }
	if state != lifecycleCommitted || err != nil {
		if state == lifecycleCommitted { s.poisoned=true; return errLifecycleCommitUnknown }
		if errors.Is(err,errLifecycleUnsafe) { s.poisoned=true }
		if err != nil { return err }; return errLifecycleUnsafe
	}
	// Do not trust a disk implementation's COMMITTED label alone. Under the
	// same mutex, safely reread and validate exact bytes and full semantics.
	readback, exists, err := s.disk.readControl()
	if err != nil || !exists || !bytes.Equal(readback,raw) { s.poisoned=true; return errLifecycleCommitUnknown }
	decoded, err := decodeLifecycleRecord(readback)
	if err != nil || s.disk.verify() != nil { s.poisoned=true; return errLifecycleCommitUnknown }
	s.record=decoded; s.raw=bytes.Clone(raw)
	return nil
}
func lifecycleAppendAudit(a *lifecycleActive,key string) {
	if a==nil{return}
	for _, existing := range a.AuditProjection { if existing==key { return } }
	a.AuditProjection=append(a.AuditProjection,key)
}
func (s *lifecycleStore) trustedNow(now time.Time) error {
	if s==nil||s.lifecycleStoreCore==nil||s.record.wire==nil{return errLifecycleUnsafe}
	if !lifecycleTime(now)||now.Before(s.record.wire.LastTrustedAt){s.poisoned=true;s.live=nil;return errLifecycleUnsafe}
	return nil
}
func (s *lifecycleStore) token(t *lifecycleOwnerToken, fresh bool, now time.Time) error {
	if err:=s.trustedNow(now);err!=nil{return err}
	if t==nil || t.lifecycleOwnerCore==nil || s.live!=t || t.store!=s || s.record.wire.Owner==nil || t.nonce!=s.record.wire.Owner.OwnerNonce || t.fence!=s.record.wire.LastFence { return errLifecycleUnsafe }
	if fresh && !now.Before(s.record.wire.Owner.ExpiresAt) { return errLifecycleUnsafe }
	return nil
}
func (s *lifecycleStore) acquireOwner(now, expires time.Time) (*lifecycleOwnerToken,error) {
	if s==nil || s.lifecycleStoreCore==nil || s.mu==nil { return nil,errLifecycleUnsafe }; s.mu.Lock(); defer s.mu.Unlock()
	if err:=s.verify();err!=nil{return nil,err}
	if err:=s.trustedNow(now);err!=nil{return nil,err}
	w:=s.record.wire
	if w.Head==nil || !lifecycleTime(expires) || !expires.After(now) ||
		w.LastFence==^uint64(0) || (w.Owner!=nil && now.Before(w.Owner.ExpiresAt)) ||
		(w.Active!=nil && !lifecycleTerminal(w.Active.Phase) && !lifecyclePrearm(w.Active)) { return nil,errLifecycleUnsafe }
	nonce:=make([]byte,32); if _,err:=io.ReadFull(rand.Reader,nonce);err!=nil{return nil,errLifecycleUnsafe}
	next,err:=s.copyRecord();if err!=nil{return nil,err}; fence:=w.LastFence+1
	// Terminal replay identity remains in tombstones; never carry a completed
	// intent into a different owner fence.
	if next.wire.Active!=nil && lifecycleTerminal(next.wire.Active.Phase) { next.wire.Active=nil }
	next.wire.LastFence=fence;next.wire.Owner=&lifecycleOwner{OwnerNonce:hex.EncodeToString(nonce),Fence:fence,AcquiredAt:now,RenewedAt:now,ExpiresAt:expires}
	if err:=s.commit(next,now);err!=nil{return nil,err}
	t:=&lifecycleOwnerToken{lifecycleOwnerCore:&lifecycleOwnerCore{store:s,nonce:next.wire.Owner.OwnerNonce,fence:fence}};s.live=t;return t,nil
}
func (s *lifecycleStore) renewOwner(t *lifecycleOwnerToken, now, expires time.Time) error {
	if s==nil||s.lifecycleStoreCore==nil||s.mu==nil{return errLifecycleUnsafe};s.mu.Lock();defer s.mu.Unlock()
	if err:=s.verify();err!=nil{return err};if err:=s.token(t,true,now);err!=nil{return err}
	if !lifecycleTime(expires)||!expires.After(now)||expires.Before(s.record.wire.Owner.ExpiresAt){return errLifecycleUnsafe}
	next,err:=s.copyRecord();if err!=nil{return err};next.wire.Owner.RenewedAt=now;next.wire.Owner.ExpiresAt=expires;return s.commit(next,now)
}
func (s *lifecycleStore) recordPlan(t *lifecycleOwnerToken,p Plan,now time.Time) error {
	if s==nil||s.lifecycleStoreCore==nil||s.mu==nil{return errLifecycleUnsafe};s.mu.Lock();defer s.mu.Unlock()
	if err:=s.verify();err!=nil{return err};if err:=s.token(t,true,now);err!=nil{return err}
	if validatePreparationPlan(p,now)!=nil || len(s.record.wire.Tombstones)>=maxLifecycleTombstones || (s.record.wire.Active!=nil&&!lifecycleTerminal(s.record.wire.Active.Phase)){return errLifecycleUnsafe}
	for _,old:=range s.record.wire.Tombstones{if old.OperationID==p.binding.OperationID||old.PlanSHA256==p.sha256{return errLifecycleUnsafe}}
	next,err:=s.copyRecord();if err!=nil{return err}
	next.wire.Active=&lifecycleActive{Plan:p.Descriptor(),Phase:"PLANNED",AuditProjection:[]string{"PLANNED"}}
	return s.commit(next,now)
}
func lifecycleApprovalID(plan PlanDescriptor) string {
	raw,_:=json.Marshal(struct { OperationID string `json:"operationId"`; PlanSHA256 string `json:"planSHA256"` }{plan.OperationID,plan.PlanSHA256})
	return labConfigHash(append([]byte("chengwang.mihomo-structural-approval-id/v1\n"),raw...))
}
func (s *lifecycleStore) recordApproval(t *lifecycleOwnerToken,m ApprovalMaterial,now time.Time) error {
	if s==nil||s.lifecycleStoreCore==nil||s.mu==nil{return errLifecycleUnsafe};s.mu.Lock();defer s.mu.Unlock()
	if err:=s.verify();err!=nil{return err};if err:=s.token(t,true,now);err!=nil{return err}
	a:=s.record.wire.Active;if a==nil||a.Phase!="PLANNED"{return errLifecycleUnsafe}
	p,err:=lifecyclePlan(a.Plan);if err!=nil||ValidateApprovalMaterial(p,m,now)!=nil{return errLifecycleUnsafe}
	next,err:=s.copyRecord();if err!=nil{return err};next.wire.Active.Approval=&lifecycleApproval{Material:m,ApprovalID:lifecycleApprovalID(a.Plan)};next.wire.Active.Phase="APPROVED";lifecycleAppendAudit(next.wire.Active,"APPROVAL_RECORDED");return s.commit(next,now)
}
func (s *lifecycleStore) recordPrepared(t *lifecycleOwnerToken,p *PreparedReload,now time.Time) error {
	if s==nil||s.lifecycleStoreCore==nil||s.mu==nil{return errLifecycleUnsafe};s.mu.Lock();defer s.mu.Unlock()
	if err:=s.verify();err!=nil{return err};if err:=s.token(t,true,now);err!=nil{return err}
	a:=s.record.wire.Active
	if a==nil||a.Phase!="APPROVED"||p==nil||!reflect.DeepEqual(p.descriptor.Plan,a.Plan)||p.descriptor.Schema!=ReloadPreparationSchema||p.descriptor.Boundary!=ReloadPreparationBoundary||
		!lifecycleTime(p.descriptor.PreparedAt)||p.descriptor.PreparedAt.After(now)||len(p.candidate)==0||len(p.backup)==0||
		labConfigHash(p.candidate)!=a.Plan.Artifact.Config.SHA256||labConfigHash(p.backup)!=a.Plan.Backup.Artifact.Config.SHA256{return errLifecycleUnsafe}
	next,err:=s.copyRecord();if err!=nil{return err};next.wire.Active.Phase="PREPARED";lifecycleAppendAudit(next.wire.Active,"PREPARED");return s.commit(next,now)
}
// recordIntent is private structural bookkeeping. It does not return a handle,
// call a controller, or confer the missing authenticated dispatch authority.
func (s *lifecycleStore) recordIntent(t *lifecycleOwnerToken,expectedHead string,now time.Time) error {
	if s==nil||s.lifecycleStoreCore==nil||s.mu==nil{return errLifecycleUnsafe};s.mu.Lock();defer s.mu.Unlock()
	if err:=s.verify();err!=nil{return err};if err:=s.token(t,true,now);err!=nil{return err}
	a:=s.record.wire.Active
	if a==nil||a.Phase!="PREPARED"||a.Attempt!=0||a.Revocation!=nil||s.record.wire.Head.HeadSHA256!=expectedHead||!now.Before(a.Plan.ExpiresAt)||!now.Before(a.Approval.Material.ExpiresAt){return errLifecycleUnsafe}
	next,err:=s.copyRecord();if err!=nil{return err};v:=&lifecycleIntent{Schema:lifecycleIntentSchema,OperationID:a.Plan.OperationID,PlanSHA256:a.Plan.PlanSHA256,
		ExpectedHeadSHA256:expectedHead,CandidateRecordSHA256:a.Plan.Artifact.RecordSHA256,BackupSHA256:a.Plan.Backup.BackupSHA256,OwnerFence:t.fence,ArmedAt:now}
	v.IntentSHA256,err=lifecycleIntentHash(*v);if err!=nil{return err};next.wire.Active.Intent=v;next.wire.Active.Attempt=1;next.wire.Active.Phase="DISPATCH_ARMED";lifecycleAppendAudit(next.wire.Active,"INTENT_ARMED");return s.commit(next,now)
}
func (s *lifecycleStore) recordResult(t *lifecycleOwnerToken,intentSHA string,result mihomo.ReloadResult,now time.Time) error {
	if s==nil||s.lifecycleStoreCore==nil||s.mu==nil{return errLifecycleUnsafe};s.mu.Lock();defer s.mu.Unlock()
	if err:=s.verify();err!=nil{return err}
	// Preserve an already-observed result even when approval/lease expired or
	// revocation was recorded while the one attempt was in flight.
	if err:=s.token(t,false,now);err!=nil{return err}
	a:=s.record.wire.Active
	if a==nil||a.Phase!="DISPATCH_ARMED"||a.Intent==nil||a.Intent.IntentSHA256!=intentSHA||a.Result!=nil||!lifecycleResultValid(result){return errLifecycleUnsafe}
	next,err:=s.copyRecord();if err!=nil{return err};n:=next.wire.Active;n.Result=&lifecycleResult{Reload:result,ObservedAt:now}
	switch result.State{case mihomo.ReloadAcknowledged:n.Phase="ACKNOWLEDGED";case mihomo.ReloadRejected:if result.Dispatched{n.Phase="RESPONSE_REJECTED"}else{n.Phase="UNSENT_REJECTED"};default:n.Phase="UNKNOWN"}
	lifecycleAppendAudit(n,"RESULT_RECORDED")
	if lifecycleTerminal(n.Phase){if err:=lifecycleAddTombstone(&next);err!=nil{return err}}
	return s.commit(next,now)
}
func lifecycleAddTombstone(r *lifecycleRecord) error {
	if r==nil||r.wire==nil||r.wire.Active==nil{return errLifecycleUnsafe}
	if len(r.wire.Tombstones)>=maxLifecycleTombstones||r.wire.Revision==^uint64(0){return errLifecycleUnsafe}
	a:=r.wire.Active;var intent *string;if a.Intent!=nil{v:=a.Intent.IntentSHA256;intent=&v}
	r.wire.Tombstones=append(r.wire.Tombstones,lifecycleTombstone{OperationID:a.Plan.OperationID,PlanSHA256:a.Plan.PlanSHA256,Attempt:a.Attempt,IntentSHA256:intent,Phase:a.Phase,TerminalRevision:r.wire.Revision+1});return nil
}
func (s *lifecycleStore) recordRevocation(t *lifecycleOwnerToken,reason,actor string,now time.Time) error {
	if s==nil||s.lifecycleStoreCore==nil||s.mu==nil{return errLifecycleUnsafe};s.mu.Lock();defer s.mu.Unlock()
	if err:=s.verify();err!=nil{return err};if err:=s.token(t,false,now);err!=nil{return err}
	a:=s.record.wire.Active;if a==nil||lifecycleTerminal(a.Phase)||!planReference.MatchString(actor)||(reason!="EXPLICIT_REVOKED"&&reason!="AUTHORITY_CHANGED"&&reason!="EXPIRED"){return errLifecycleUnsafe}
	next,err:=s.copyRecord();if err!=nil{return err};n:=next.wire.Active;revision:=uint64(1);if n.Revocation!=nil{if n.Revocation.Revision==^uint64(0){return errLifecycleUnsafe};revision=n.Revocation.Revision+1}
	n.Revocation=&lifecycleRevocation{Revision:revision,At:now,Reason:reason,ActorRef:actor};lifecycleAppendAudit(n,"REVOCATION_RECORDED")
	if n.Attempt==0{n.Phase="REVOKED";if err:=lifecycleAddTombstone(&next);err!=nil{return err}}
	return s.commit(next,now)
}
func (s *lifecycleStore) close() error {
	if s==nil||s.lifecycleStoreCore==nil||s.mu==nil{return errLifecycleUnsafe};s.mu.Lock();defer s.mu.Unlock();if s.closed{return errLifecycleUnsafe};s.closed=true;s.live=nil
	if s.disk==nil{return errLifecycleUnsafe};return s.disk.close()
}
