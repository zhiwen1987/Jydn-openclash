//go:build linux && chengwang_mihomo_recovery_continuous_fault && chengwang_mihomo_recovery_native

package mihomodeploy

import (
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"sync"
	"time"

	"chengwang/internal/adapter/mihomo"
)

const labContinuousRecoveryFaultDebug = "private continuous recovery response-loss schedule"
const labContinuousRecoveryFaultSchema = "chengwang.mihomo-continuous-recovery-response-loss/v1"

type LabContinuousRecoveryNativeCall struct {
	Sequence int       `json:"sequence"`
	Kind     string    `json:"kind"`
	Core     uint64    `json:"core"`
	At       time.Time `json:"at"`
}

type LabContinuousRecoveryFaultObservation struct {
	Schema             string                                          `json:"schema"`
	State              string                                          `json:"state"`
	BoundOperations    int                                             `json:"boundOperations"`
	ObservedResults    int                                             `json:"observedResults"`
	InitialCore        uint64                                          `json:"initialCore"`
	RecoveredCore      *uint64                                         `json:"recoveredCore"`
	NativeCallsBounded bool                                            `json:"nativeCallsBounded"`
	NativeCalls        []LabContinuousRecoveryNativeCall               `json:"nativeCalls"`
	Transport          mihomo.LabReloadResponseLossScheduleObservation `json:"transport"`
}

type labContinuousRecoveryFaultIssuer struct {
	mu        sync.Mutex
	attempted bool
	issued    *LabContinuousRecoveryFaultHandle
}

type labContinuousRecoveryFaultCore struct {
	issuer           *labContinuousRecoveryFaultIssuer
	identity         *labContinuousRecoveryFaultCore
	service          *labServiceCore
	runtime          *labLifecycleRuntimeCore
	initialStore     *lifecycleStore
	initialOwner     *lifecycleOwnerToken
	initialKernel    *ownedLabKernel
	initialCore      uint64
	recoveredCore    *uint64
	nativePrefix     int
	nativeLast       int
	transport        *mihomo.LabReloadResponseLossSchedule
	claims           [3]*labContinuousRecoveryFaultClaim
	bound            int
	observed         int
	firstOperation   string
	firstPlan        string
	currentBackend   *lifecycleCurrentEpochBackend
	currentAnchorSHA string
	closed           bool
	poisoned         bool
	operations       map[string]bool
}

type LabContinuousRecoveryFaultHandle struct {
	core *labContinuousRecoveryFaultCore
}

type labContinuousRecoveryFaultClaim struct {
	root         *labContinuousRecoveryFaultCore
	service      *labServiceCore
	writer       *mihomo.WriteClient
	prepared     *preparedReloadCore
	session      *labSessionCore
	store        *lifecycleStore
	owner        *lifecycleOwnerToken
	kernel       *ownedLabKernel
	backend      *lifecycleCurrentEpochBackend
	child        *mihomo.LabReloadResponseLossChild
	operationID  string
	planSHA256   string
	intentSHA256 string
	revision     uint64
	recordSHA256 string
	observed     bool
}

var processLabContinuousRecoveryFaultIssuer labContinuousRecoveryFaultIssuer

func (LabContinuousRecoveryFaultHandle) String() string   { return labContinuousRecoveryFaultDebug }
func (LabContinuousRecoveryFaultHandle) GoString() string { return labContinuousRecoveryFaultDebug }
func (LabContinuousRecoveryFaultHandle) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, labContinuousRecoveryFaultDebug)
}
func (LabContinuousRecoveryFaultHandle) MarshalJSON() ([]byte, error) {
	return []byte(`{"scope":"PRIVATE_CONTINUOUS_RECOVERY_FAULT_NOT_AUTHORIZATION"}`), nil
}
func (*LabContinuousRecoveryFaultHandle) UnmarshalJSON([]byte) error { return errLifecycleUnsafe }

func labContinuousRecoveryIssued(i *labContinuousRecoveryFaultIssuer, h *LabContinuousRecoveryFaultHandle) bool {
	return i != nil && h != nil && h.core != nil && i.attempted && i.issued == h && h.core.issuer == i &&
		h.core.identity == h.core && h.core.service != nil && h.core.runtime != nil && h.core.transport != nil
}

// BeginLabContinuousRecoveryResponseLoss binds the sole schedule to this
// actual warm service. No request header, environment value, operation DTO,
// URL, PID or serialized record can issue it.
func BeginLabContinuousRecoveryResponseLoss(service *LabService) (*LabContinuousRecoveryFaultHandle, error) {
	if service == nil || service.core == nil {
		return nil, errLifecycleUnsafe
	}
	s := service.core
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.closing || s.busy || !s.ready || s.runtime == nil || s.runtime.core == nil ||
		s.store == nil || s.owner == nil || s.owner.lifecycleOwnerCore == nil || s.kernel == nil {
		return nil, errLifecycleUnsafe
	}
	runtime := s.runtime.core
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.closed || runtime.poisoned || runtime.store != s.store || runtime.recovery != nil || runtime.current != nil ||
		s.store.currentEpoch != nil || s.owner.store != s.store || s.store.live != s.owner {
		return nil, errLifecycleUnsafe
	}
	s.store.mu.Lock()
	if s.store.verify() != nil || s.store.record.wire == nil || s.store.record.wire.Head == nil || s.store.record.wire.Active != nil {
		s.store.mu.Unlock()
		return nil, errLifecycleUnsafe
	}
	s.store.mu.Unlock()
	initialCore, ok := labNativeRecoveryReadCore(s.kernel)
	if !ok {
		return nil, errLifecycleUnsafe
	}
	events, bounded := labNativeRecoveryReadCalls()
	if !bounded || len(events) > 256 {
		return nil, errLifecycleUnsafe
	}
	last := 0
	if len(events) != 0 {
		last = events[len(events)-1].Sequence
	}
	i := &processLabContinuousRecoveryFaultIssuer
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.attempted {
		return nil, errLifecycleUnsafe
	}
	i.attempted = true
	transport, err := mihomo.BeginLabReloadResponseLossSchedule()
	if err != nil {
		return nil, errLifecycleUnsafe
	}
	core := &labContinuousRecoveryFaultCore{issuer: i, service: s, runtime: runtime, initialStore: s.store,
		initialOwner: s.owner, initialKernel: s.kernel, initialCore: initialCore, nativePrefix: len(events), nativeLast: last,
		transport: transport, operations: map[string]bool{}}
	core.identity = core
	h := &LabContinuousRecoveryFaultHandle{core: core}
	i.issued = h
	return h, nil
}

func (h *LabContinuousRecoveryFaultHandle) Close() error {
	if h == nil || h.core == nil || h.core.issuer == nil {
		return errLifecycleUnsafe
	}
	i := h.core.issuer
	i.mu.Lock()
	defer i.mu.Unlock()
	if !labContinuousRecoveryIssued(i, h) {
		return errLifecycleUnsafe
	}
	h.core.closed = true
	if h.core.transport.Close() != nil {
		h.core.poisoned = true
		return errLifecycleUnsafe
	}
	return nil
}

func (h *LabContinuousRecoveryFaultHandle) Observe() (LabContinuousRecoveryFaultObservation, error) {
	var zero LabContinuousRecoveryFaultObservation
	if h == nil || h.core == nil || h.core.issuer == nil {
		return zero, errLifecycleUnsafe
	}
	i := h.core.issuer
	i.mu.Lock()
	defer i.mu.Unlock()
	if !labContinuousRecoveryIssued(i, h) {
		return zero, errLifecycleUnsafe
	}
	core := h.core
	transport, err := core.transport.Observe()
	if err != nil {
		return zero, errLifecycleUnsafe
	}
	events, bounded := labNativeRecoveryReadCalls()
	if core.nativePrefix > len(events) || !bounded {
		core.poisoned = true
		return zero, errLifecycleUnsafe
	}
	calls := make([]LabContinuousRecoveryNativeCall, 0, len(events)-core.nativePrefix)
	for _, event := range events[core.nativePrefix:] {
		if event.Sequence <= core.nativeLast {
			core.poisoned = true
			return zero, errLifecycleUnsafe
		}
		calls = append(calls, LabContinuousRecoveryNativeCall{Sequence: event.Sequence, Kind: event.Kind, Core: event.Core, At: event.At})
	}
	state := "ACTIVE"
	if core.poisoned {
		state = "POISONED"
	} else if core.closed {
		state = "CLOSED"
	} else if core.observed == len(core.claims) {
		state = "TERMINAL"
	}
	var recovered *uint64
	if core.recoveredCore != nil {
		value := *core.recoveredCore
		recovered = &value
	}
	return LabContinuousRecoveryFaultObservation{Schema: labContinuousRecoveryFaultSchema, State: state,
		BoundOperations: core.bound, ObservedResults: core.observed, InitialCore: core.initialCore, RecoveredCore: recovered,
		NativeCallsBounded: bounded, NativeCalls: calls, Transport: transport}, nil
}

func labContinuousRecoveryCurrentLocked(root *labContinuousRecoveryFaultCore, service *labServiceCore, sequence int) (*lifecycleCurrentEpochBackend, string, error) {
	if root == nil || service == nil || service.runtime == nil || service.runtime.core != root.runtime || service.store == nil ||
		service.owner == nil || service.kernel == nil || service.store.live != service.owner {
		return nil, "", errLifecycleUnsafe
	}
	runtime := root.runtime
	if runtime.closed || runtime.poisoned || runtime.store != nil || runtime.recovery == nil || runtime.current != service.store {
		return nil, "", errLifecycleUnsafe
	}
	backend, err := service.store.currentEpochBinding()
	if err != nil || backend == nil || backend.identity != backend || backend.projection != service.store || backend.store != runtime.recovery.core ||
		backend.token == nil || backend.store.currentLive != backend.token || !lifecycleCurrentHandoffHistoryPaired(backend.store.record.core) {
		return nil, "", errLifecycleUnsafe
	}
	w := backend.store.record.core
	tail := &w.RecoveryHistory[len(w.RecoveryHistory)-1]
	if tail.Plan.UnknownOperationID != root.firstOperation || tail.Plan.OriginalPlanSHA256 != root.firstPlan {
		return nil, "", errLifecycleUnsafe
	}
	anchorSHA, err := lifecycleHash(w.Current.Anchor)
	if err != nil || !lifecycleNonzeroHash(anchorSHA) {
		return nil, "", errLifecycleUnsafe
	}
	if sequence == 2 {
		if root.currentBackend != nil || root.currentAnchorSHA != "" {
			return nil, "", errLifecycleUnsafe
		}
		root.currentBackend, root.currentAnchorSHA = backend, anchorSHA
		core, ok := labNativeRecoveryReadCore(service.kernel)
		if !ok || core == root.initialCore {
			return nil, "", errLifecycleUnsafe
		}
		root.recoveredCore = &core
	} else {
		if sequence != 3 || backend != root.currentBackend || anchorSHA != root.currentAnchorSHA || len(w.Current.Completed) == 0 {
			return nil, "", errLifecycleUnsafe
		}
		second := root.claims[1]
		completion := &w.Current.Completed[len(w.Current.Completed)-1]
		if second == nil || completion.Active.Plan.OperationID != second.operationID || completion.Active.Plan.PlanSHA256 != second.planSHA256 ||
			completion.Active.Result == nil || completion.Active.Result.Reload.State != mihomo.ReloadAcknowledged {
			return nil, "", errLifecycleUnsafe
		}
	}
	return backend, anchorSHA, nil
}

// Called with service.mu after the ordinary path has recorded Intent and
// repeated authorization/owned-kernel checks, but before it claims Reload.
func labContinuousRecoveryBeforeReload(service *labServiceCore, writer *mihomo.WriteClient, prepared *PreparedReload, operationID, intentSHA256 string) error {
	i := &processLabContinuousRecoveryFaultIssuer
	i.mu.Lock()
	defer i.mu.Unlock()
	if !i.attempted || i.issued == nil {
		return nil
	}
	if !labContinuousRecoveryIssued(i, i.issued) || i.issued.core.service != service {
		// A different service is outside this schedule and cannot consume it.
		return nil
	}
	root := i.issued.core
	if root.closed || root.poisoned || root.bound >= len(root.claims) || root.operations[operationID] ||
		writer == nil || prepared == nil || prepared.preparedReloadCore == nil || service.runtime == nil || service.runtime.core != root.runtime {
		root.poisoned = true
		return errLifecycleUnsafe
	}
	if root.bound != root.observed {
		root.poisoned = true
		return errLifecycleUnsafe
	}
	runtime := root.runtime
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	store := service.store
	session := service.sessions[operationID]
	if store == nil || store.mu == nil || service.owner == nil || service.owner.lifecycleOwnerCore == nil || service.kernel == nil ||
		session == nil || session.core == nil || service.authority == nil || service.authority.core == nil {
		root.poisoned = true
		return errLifecycleUnsafe
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.verify() != nil || store.record.wire == nil || store.record.wire.Active == nil || store.record.wire.Active.Intent == nil ||
		store.record.wire.Active.Phase != "DISPATCH_ARMED" || store.record.wire.Active.Plan.OperationID != operationID ||
		store.record.wire.Active.Intent.IntentSHA256 != intentSHA256 || !reflect.DeepEqual(store.record.wire.Active.Plan, prepared.descriptor.Plan) ||
		len(prepared.candidate) == 0 || labConfigHash(prepared.candidate) != prepared.descriptor.Plan.Artifact.Config.SHA256 ||
		service.once[intentSHA256] != "ARMED" || store.live != service.owner || service.owner.store != store ||
		session.core.authority != service.authority.core || session.core.store != store || session.core.owner != service.owner ||
		session.core.fence != service.owner.fence || !reflect.DeepEqual(session.core.plan, store.record.wire.Active.Plan) {
		root.poisoned = true
		return errLifecycleUnsafe
	}
	sequence := root.bound + 1
	var backend *lifecycleCurrentEpochBackend
	if sequence == 1 {
		if store != root.initialStore || service.owner != root.initialOwner || service.kernel != root.initialKernel ||
			runtime.store != store || runtime.recovery != nil || runtime.current != nil || store.currentEpoch != nil {
			root.poisoned = true
			return errLifecycleUnsafe
		}
		root.firstOperation, root.firstPlan = operationID, store.record.wire.Active.Plan.PlanSHA256
	} else {
		var err error
		backend, _, err = labContinuousRecoveryCurrentLocked(root, service, sequence)
		if err != nil {
			root.poisoned = true
			return errLifecycleUnsafe
		}
	}
	child, err := root.transport.Bind(writer)
	if err != nil || child == nil {
		root.poisoned = true
		return errLifecycleUnsafe
	}
	claim := &labContinuousRecoveryFaultClaim{root: root, service: service, writer: writer, prepared: prepared.preparedReloadCore,
		session: session.core, store: store, owner: service.owner, kernel: service.kernel, backend: backend,
		child: child, operationID: operationID, planSHA256: store.record.wire.Active.Plan.PlanSHA256,
		intentSHA256: intentSHA256, revision: store.record.wire.Revision, recordSHA256: store.record.wire.RecordSHA256}
	root.claims[root.bound] = claim
	root.operations[operationID] = true
	root.bound++
	return nil
}

// Called by defer after the ordinary execute function has made every existing
// result/observation recording attempt. It is diagnostic state only and cannot
// suppress, replay or replace an already-dispatched write.
func labContinuousRecoveryAfterReload(service *labServiceCore, writer *mihomo.WriteClient, prepared *PreparedReload, operationID, intentSHA256 string, result mihomo.ReloadResult) {
	i := &processLabContinuousRecoveryFaultIssuer
	i.mu.Lock()
	defer i.mu.Unlock()
	if !i.attempted || i.issued == nil || !labContinuousRecoveryIssued(i, i.issued) || i.issued.core.service != service {
		return
	}
	root := i.issued.core
	if root.observed >= root.bound {
		root.poisoned = true
		return
	}
	claim := root.claims[root.observed]
	if claim == nil || claim.root != root || claim.service != service || claim.writer != writer || claim.prepared != prepared.preparedReloadCore ||
		claim.operationID != operationID || claim.intentSHA256 != intentSHA256 || claim.observed {
		root.poisoned = true
		return
	}
	step, err := claim.child.Observe()
	expectedLoss := step.Sequence == 1 || step.Sequence == 3
	if err != nil || step.Sequence != root.observed+1 || step.UnderlyingRoundTrips != 1 ||
		(expectedLoss && (!step.Injected || step.State != "INJECTED" || result.State != mihomo.ReloadUnknown || !result.Dispatched || result.StatusCode != 0)) ||
		(!expectedLoss && (step.Injected || step.State != "PASSTHROUGH" || result.State != mihomo.ReloadAcknowledged || !result.Dispatched || result.StatusCode != 204)) {
		root.poisoned = true
		return
	}
	claim.observed = true
	root.observed++
}

var _ json.Marshaler = LabContinuousRecoveryFaultHandle{}
