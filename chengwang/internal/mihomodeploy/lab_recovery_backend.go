package mihomodeploy

import (
	"context"
	"reflect"
	"sync"
	"time"

	"chengwang/internal/authz"
)

const LabRecoveryViewSchema = "chengwang.mihomo-lab-recovery-view/v2"
const LabRecoveryFailureViewSchema = "chengwang.mihomo-lab-recovery-failure-view/v1"

// LabRecoveryBackend is a stable facade over the same live LabService. Every
// call receives only that request's original Authorization values.
type LabRecoveryBackend interface {
	Scope() authz.ResourceScope
	Create(context.Context, []string, LabRecoveryCreateRequest) (LabRecoveryView, error)
	Inspect(context.Context, []string, string) (LabRecoveryView, error)
	Approve(context.Context, []string, string, LabRecoveryApprovalRequest) (LabRecoveryView, error)
	Execute(context.Context, []string, string, LabRecoveryExecuteRequest) (LabRecoveryView, error)
	Revoke(context.Context, []string, string, LabRecoveryRevokeRequest) (LabRecoveryView, error)
}

type LabRecoveryCreateRequest struct {
	UnknownOperationID string `json:"unknownOperationId"`
	OriginalPlanSHA256 string `json:"originalPlanSHA256"`
	Revision           uint64 `json:"revision"`
	TTLSeconds         uint16 `json:"ttlSeconds"`
}

type LabRecoveryApprovalRequest struct {
	PlanSHA256 string `json:"planSHA256"`
	Revision   uint64 `json:"revision"`
}

type LabRecoveryExecuteRequest struct {
	PlanSHA256 string `json:"planSHA256"`
	Revision   uint64 `json:"revision"`
}

type LabRecoveryRevokeRequest struct {
	PlanSHA256 string `json:"planSHA256"`
	Revision   uint64 `json:"revision"`
	Reason     string `json:"reason"`
}

type LabRecoveryView struct {
	Schema                     string       `json:"schema"`
	Boundary                   string       `json:"boundary"`
	RecoveryID                 string       `json:"recoveryId"`
	Phase                      string       `json:"phase"`
	Revision                   uint64       `json:"revision"`
	PlanSHA256                 string       `json:"planSHA256"`
	UnknownOperationID         string       `json:"unknownOperationId"`
	OriginalPlanSHA256         string       `json:"originalPlanSHA256"`
	PreviousHeadSHA256         string       `json:"previousHeadSHA256"`
	HeadSHA256                 string       `json:"headSHA256"`
	HeadGeneration             uint64       `json:"headGeneration"`
	TargetArtifactRecordSHA256 string       `json:"targetArtifactRecordSHA256"`
	TargetConfigSHA256         string       `json:"targetConfigSHA256"`
	ExpiresAt                  time.Time    `json:"expiresAt"`
	WriteBlocked               bool         `json:"writeBlocked"`
	Replayed                   bool         `json:"replayed"`
	HeadAdvanced               bool         `json:"headAdvanced"`
	Failure                    *LabRecoveryFailureView `json:"failure,omitempty"`
	Proof                      LabProofView `json:"proof"`
}

// Failure is detached status only. CleanupSHA256 names the source-derived
// private cleanup receipt; it cannot authorize reconciliation or another Start.
type LabRecoveryFailureView struct {
	Schema        string `json:"schema"`
	Code          string `json:"code"`
	CleanupState  string `json:"cleanupState"`
	CleanupSHA256 string `json:"cleanupSHA256,omitempty"`
	NextAction    string `json:"nextAction"`
}

type labRecoveryBackend struct{ service *LabService }

const (
	labRecoveryReconcileReady      = "READY"
	labRecoveryReconcileArmed      = "ARMED"
	labRecoveryReconcileCommitting = "COMMITTING"
	labRecoveryReconcileCommitted  = "COMMITTED"
	labRecoveryReconcileLocked     = "LOCKED"
	labRecoveryReconcileMaxAttempts = 2
)

// Keep the caller-derived deadline and cancellation live through capability
// consumption and the corresponding record call. The deferred cancellation is
// observable after action returns, never while the record method is running.
func labRecoveryWithRecordContext(parent context.Context, budget time.Duration, action func(context.Context) error) error {
	if parent == nil || budget <= 0 || action == nil || artifactContext(parent) != nil {
		return errLifecycleUnsafe
	}
	ctx, cancel := context.WithTimeout(parent, budget)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	return action(ctx)
}

type labRecoveryOperation struct {
	id        string
	session   *labRecoverySession
	store     *lifecycleRecoveryStore
	owner     *lifecycleRecoveryOwnerToken
	plan      labRecoveryPlanDescriptor
	executing bool
	settled   bool
	old       *ownedLabKernel
	oldIdentity labKernelIdentity
	oldExit   *labKernelExit
	quiescence *labQuiescenceObservation
	next      *ownedLabKernel
	nextIdentity *labKernelIdentity
	startObservation *labRecoveryStartObservation
	executorRef string
	physical    bool
	startedRecorded bool
	completionCommitted bool
	failureCode string
	failureRecorded bool
	failure     *LabRecoveryFailureView
	cleanup     *labRecoveryCleanupCustody
	reentry     *labRecoveryTerminalReentryPermit
	sourceCleanup *labRecoveryCleanupCustody
	sourceReentry *labRecoveryTerminalReentryPermit
	reconcileState string
	reconcileAttempts uint8
}

// These helpers are called only while the exact service mutex is held. A
// READY custody permits one explicit retry after the initial automatic
// reconciliation attempt. Once a core permit has been issued, or publication
// has been attempted, failure is terminal: neither the physical cleanup nor a
// possibly consumed capability is replayed.
func (o *labRecoveryOperation) reconciliationRetryable() bool {
	return o != nil && o.reconcileState == labRecoveryReconcileReady &&
		o.reconcileAttempts < labRecoveryReconcileMaxAttempts && o.reentry == nil &&
		o.cleanup != nil && o.cleanup.matches(o)
}

func (o *labRecoveryOperation) reconciliationCheckMatches(check labRecoveryCheck) bool {
	return o != nil && check.core != nil && check.core.action == "RECOVERY_RECONCILE_AUTHORIZATION_CHECK" &&
		check.core.actorRef == o.plan.DeclaredInitiatorRef && check.core.recoveryID == o.id &&
		check.core.planSHA256 == o.plan.PlanSHA256 && check.core.revision != 0 &&
		lifecycleNonzeroHash(check.core.recordSHA256) && o.owner != nil && o.owner.core != nil &&
		check.core.fence == o.owner.core.fence && check.core.intentSHA256 == o.failureCode && o.failureCode != ""
}

func (o *labRecoveryOperation) reconciliationCheckCurrent(check labRecoveryCheck) bool {
	if !o.reconciliationCheckMatches(check) || o.store == nil || o.store.core == nil {
		return false
	}
	o.store.core.mu.Lock()
	defer o.store.core.mu.Unlock()
	w := o.store.core.record.core
	return w != nil && w.Recovery != nil && w.RecoveryOwner != nil && w.Recovery.Phase == "RECOVERY_UNKNOWN" &&
		w.Recovery.Failure != nil && w.Recovery.Failure.Code == o.failureCode && w.Recovery.Revocation == nil &&
		reflect.DeepEqual(w.Recovery.Plan, o.plan) && w.Revision == check.core.revision &&
		w.RecordSHA256 == check.core.recordSHA256 && w.LastRecoveryFence == check.core.fence &&
		w.RecoveryOwner.Fence == check.core.fence
}

func (o *labRecoveryOperation) beginAuthorizedReconciliationAttempt(expected *labRecoveryCleanupCustody, check labRecoveryCheck) bool {
	if o == nil || expected == nil || o.cleanup != expected || !o.reconciliationRetryable() || !o.reconciliationCheckMatches(check) {
		return false
	}
	o.reconcileAttempts++
	return true
}

func (o *labRecoveryOperation) beginCurrentAuthorizedReconciliationAttempt(expected *labRecoveryCleanupCustody, check labRecoveryCheck) bool {
	return o.reconciliationCheckCurrent(check) && o.beginAuthorizedReconciliationAttempt(expected, check)
}

func (o *labRecoveryOperation) reconciliationPrePermitFailed() bool {
	if o != nil && o.reconcileAttempts >= labRecoveryReconcileMaxAttempts {
		o.reconcileState = labRecoveryReconcileLocked
		return true
	}
	return false
}

type labRecoveryCleanupProbe struct {
	Role       string             `json:"role"`
	ObservedAt time.Time          `json:"observedAt"`
	Probe      labQuiescenceProbe `json:"probe"`
}

// Memory-only custody of the actual failed-kernel cleanup. It preserves the
// canonical receipt for a future typed core reconciliation contract, but cannot
// itself archive UNKNOWN, mint a Plan, approve, execute or restart a kernel.
type labRecoveryCleanupCustody struct {
	issuer    *labRecoveryCleanupIssuer
	operation *labRecoveryOperation
	service   *labServiceCore
	runtime   *labLifecycleRuntimeCore
	store     *lifecycleRecoveryStoreCore
	disk      labRuntimeDisk
	diagnostics *labDiagnosticsCore
	owner     *lifecycleRecoveryOwnerCore
	old       *ownedLabKernelCore
	next      *ownedLabKernelCore
	unstartedNext *labRecoveryUnstartedCleanupCustody
	oldIdentity  labKernelIdentity
	nextIdentity *labKernelIdentity
	oldExit      labKernelExit
	nextExit     *labKernelExit
	attempt      *labRecoveryStartObservation
	probes       [4]labRecoveryCleanupProbe
	oldStdoutSHA256  string
	oldStderrSHA256  string
	nextStdoutSHA256 string
	nextStderrSHA256 string
	oldStdoutBytes   int
	oldStderrBytes   int
	nextStdoutBytes  int
	nextStderrBytes  int
	observedAt time.Time
	failureCode string
	canonical string
	digest    string
	settled   bool
	used      bool
	binding   func(*labRecoveryCleanupCustody, *labRecoveryOperation) bool
}

const labRecoveryUnstartedCleanupSchema = "chengwang.mihomo-recovery-unstarted-kernel-cleanup/v1"

type labRecoveryUnstartedCleanupReceipt struct {
	Schema      string                    `json:"schema"`
	Observation labKernelStartObservation `json:"observation"`
	Stdout      labKernelStream            `json:"stdout"`
	Stderr      labKernelStream            `json:"stderr"`
	ObservedAt  time.Time                  `json:"observedAt"`
}

// labRecoveryUnstartedCleanupCustody is a memory-only, source-issued proof
// that an owned wrapper reached a known Start(false) result without ever
// acquiring an OS process identity. It is issued and consumed atomically with
// its parent cleanup custody; it is never a persisted New-kernel authority.
type labRecoveryUnstartedCleanupCustody struct {
	issuer      *labRecoveryCleanupIssuer
	parent      *labRecoveryCleanupCustody
	operation   *labRecoveryOperation
	service     *labServiceCore
	kernel      *ownedLabKernelCore
	observation labKernelStartObservation
	stdout      labKernelStream
	stderr      labKernelStream
	stdoutSHA256 string
	stderrSHA256 string
	stdoutBytes int
	stderrBytes int
	observedAt  time.Time
	used        bool
	binding     func(*labRecoveryUnstartedCleanupCustody, *labRecoveryCleanupCustody, *labRecoveryOperation) bool
}

func (labRecoveryUnstartedCleanupCustody) MarshalJSON() ([]byte, error) { return nil, errLifecycleUnsafe }
func (c *labRecoveryUnstartedCleanupCustody) UnmarshalJSON([]byte) error {
	if c != nil {
		*c = labRecoveryUnstartedCleanupCustody{}
	}
	return errLifecycleUnsafe
}

type labRecoveryCleanupIssuer struct {
	mu     sync.Mutex
	issued map[*labRecoveryCleanupCustody]bool
}

var processLabRecoveryCleanupIssuer = labRecoveryCleanupIssuer{issued: map[*labRecoveryCleanupCustody]bool{}}

func (i *labRecoveryCleanupIssuer) issue(c *labRecoveryCleanupCustody) bool {
	if i == nil || c == nil {
		return false
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.issued == nil || i.issued[c] || len(i.issued) >= labServiceOperationLimit ||
		(c.unstartedNext != nil && !c.unstartedNext.matches(c, c.operation)) {
		return false
	}
	i.issued[c] = true
	return true
}

func (i *labRecoveryCleanupIssuer) claim(c *labRecoveryCleanupCustody) (*labRecoveryUnstartedCleanupCustody, bool) {
	if i == nil || c == nil {
		return nil, false
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	u := c.unstartedNext
	if c.used || i.issued == nil || !i.issued[c] ||
		(u != nil && (u.used || u.issuer != i || u.parent != c)) {
		return nil, false
	}
	delete(i.issued, c)
	c.used = true
	if u != nil {
		u.used = true
	}
	return u, true
}

// discard wins or loses atomically against claim for the exact issued parent.
// It releases the parent/child object graph without consuming cleanup facts or
// minting a reconciliation authority. Copies and foreign operations are not
// map keys and cannot discard another source's custody.
func (i *labRecoveryCleanupIssuer) discard(c *labRecoveryCleanupCustody, op *labRecoveryOperation) bool {
	if i == nil || c == nil || op == nil {
		return false
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	u := c.unstartedNext
	if c.issuer != i || c.operation != op || c.used || i.issued == nil || !i.issued[c] ||
		(u != nil && (u.issuer != i || u.parent != c || u.operation != op || u.used)) {
		return false
	}
	delete(i.issued, c)
	*c = labRecoveryCleanupCustody{used: true}
	if u != nil {
		*u = labRecoveryUnstartedCleanupCustody{used: true}
	}
	return true
}

func (i *labRecoveryCleanupIssuer) contains(c *labRecoveryCleanupCustody) bool {
	if i == nil || c == nil {
		return false
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.issued != nil && i.issued[c]
}

type labRecoveryAbsentStartCustody struct {
	issuer    *labRecoveryAbsentStartIssuer
	operation *labRecoveryOperation
	service   *labServiceCore
	runtime   *labLifecycleRuntimeCore
	store     *lifecycleRecoveryStoreCore
	disk      labRuntimeDisk
	owner     *lifecycleRecoveryOwnerCore
	reentry   *labRecoveryTerminalReentryPermitCore
	oldIdentity labKernelIdentity
	cleanupSHA string
	terminalRoot string
	terminalCanonical string
	planSHA   string
	recoveryID string
	probes    [2]labRecoveryCleanupProbe
	observedAt time.Time
	used      bool
	binding   func(*labRecoveryAbsentStartCustody) bool
}

type labRecoveryAbsentStartIssuer struct {
	mu     sync.Mutex
	issued map[*labRecoveryAbsentStartCustody]bool
}

func (labRecoveryAbsentStartCustody) MarshalJSON() ([]byte, error) { return nil, errLifecycleUnsafe }
func (c *labRecoveryAbsentStartCustody) UnmarshalJSON([]byte) error {
	if c != nil {
		*c = labRecoveryAbsentStartCustody{}
	}
	return errLifecycleUnsafe
}

var processLabRecoveryAbsentStartIssuer = labRecoveryAbsentStartIssuer{issued: map[*labRecoveryAbsentStartCustody]bool{}}

func (i *labRecoveryAbsentStartIssuer) issue(c *labRecoveryAbsentStartCustody) bool {
	if i == nil || c == nil {
		return false
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.issued == nil || i.issued[c] || len(i.issued) >= labServiceOperationLimit {
		return false
	}
	i.issued[c] = true
	return true
}

type labRecoveryAbsentReentryCustody struct {
	issuer    *labRecoveryAbsentReentryIssuer
	operation *labRecoveryOperation
	service   *labServiceCore
	runtime   *labLifecycleRuntimeCore
	store     *lifecycleRecoveryStoreCore
	disk      labRuntimeDisk
	owner     *lifecycleRecoveryOwnerCore
	reentry   *labRecoveryTerminalReentryPermitCore
	sourceCleanup *labRecoveryCleanupCustody
	oldIdentity labKernelIdentity
	cleanupSHA string
	terminalRoot string
	terminalCanonical string
	planSHA string
	recoveryID string
	used bool
	binding func(*labRecoveryAbsentReentryCustody) bool
}

type labRecoveryAbsentReentryIssuer struct {
	mu sync.Mutex
	issued map[*labRecoveryAbsentReentryCustody]bool
}

var processLabRecoveryAbsentReentryIssuer = labRecoveryAbsentReentryIssuer{issued: map[*labRecoveryAbsentReentryCustody]bool{}}

func (labRecoveryAbsentReentryCustody) MarshalJSON() ([]byte, error) { return nil, errLifecycleUnsafe }
func (c *labRecoveryAbsentReentryCustody) UnmarshalJSON([]byte) error {
	if c != nil {
		*c = labRecoveryAbsentReentryCustody{}
	}
	return errLifecycleUnsafe
}

func (i *labRecoveryAbsentReentryIssuer) issue(c *labRecoveryAbsentReentryCustody) bool {
	if i == nil || c == nil {
		return false
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.issued == nil || i.issued[c] || len(i.issued) >= labServiceOperationLimit {
		return false
	}
	i.issued[c] = true
	return true
}

type labRecoveryLiveReentryCustody struct {
	issuer   *labRecoveryLiveReentryIssuer
	service  *labServiceCore
	runtime  *labLifecycleRuntimeCore
	store    *lifecycleRecoveryStoreCore
	disk     labRuntimeDisk
	owner    *lifecycleRecoveryOwnerCore
	kernel   *ownedLabKernelCore
	identity labKernelIdentity
	recoveryID string
	used     bool
	binding  func(*labRecoveryLiveReentryCustody) bool
}

type labRecoveryLiveReentryIssuer struct {
	mu     sync.Mutex
	issued map[*labRecoveryLiveReentryCustody]bool
}

func (labRecoveryLiveReentryCustody) MarshalJSON() ([]byte, error) { return nil, errLifecycleUnsafe }
func (c *labRecoveryLiveReentryCustody) UnmarshalJSON([]byte) error {
	if c != nil {
		*c = labRecoveryLiveReentryCustody{}
	}
	return errLifecycleUnsafe
}

var processLabRecoveryLiveReentryIssuer = labRecoveryLiveReentryIssuer{issued: map[*labRecoveryLiveReentryCustody]bool{}}

func (i *labRecoveryLiveReentryIssuer) issue(c *labRecoveryLiveReentryCustody) bool {
	if i == nil || c == nil {
		return false
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.issued == nil || i.issued[c] || len(i.issued) >= labServiceOperationLimit {
		return false
	}
	i.issued[c] = true
	return true
}

func (c labRecoveryCleanupCustody) MarshalJSON() ([]byte, error) { return nil, errLifecycleUnsafe }
func (c *labRecoveryCleanupCustody) UnmarshalJSON([]byte) error {
	if c != nil {
		*c = labRecoveryCleanupCustody{}
	}
	return errLifecycleUnsafe
}
func (c *labRecoveryCleanupCustody) matches(op *labRecoveryOperation) bool {
	return c != nil && !c.used && c.binding != nil && lifecycleNonzeroHash(c.digest) && len(c.canonical) != 0 && c.binding(c, op) &&
		(c.unstartedNext == nil || c.unstartedNext.matches(c, op))
}

func (c *labRecoveryUnstartedCleanupCustody) matches(parent *labRecoveryCleanupCustody, op *labRecoveryOperation) bool {
	return c != nil && parent != nil && !c.used && c.issuer != nil && c.issuer == parent.issuer && c.parent == parent &&
		c.operation == op && c.service != nil && c.kernel != nil && c.binding != nil &&
		lifecycleTime(c.observedAt) && lifecycleNonzeroHash(c.stdoutSHA256) && lifecycleNonzeroHash(c.stderrSHA256) &&
		c.stdoutBytes >= 0 && c.stdoutBytes <= 64<<10 && c.stderrBytes >= 0 && c.stderrBytes <= 64<<10 &&
		c.binding(c, parent, op)
}

type labRecoveryCoordinator struct {
	service    *LabService
	authority  *labRecoveryAuthority
	store      *lifecycleRecoveryStore
	owner      *lifecycleRecoveryOwnerToken
	operations map[string]*labRecoveryOperation
	activeID   string
	closed     bool
}

func newLabRecoveryCoordinator(service *LabService) (*labRecoveryCoordinator, error) {
	if service == nil || service.core == nil || service.core.authority == nil {
		return nil, errLifecycleUnsafe
	}
	authority, err := newLabRecoveryAuthority(service.core.authority, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	return &labRecoveryCoordinator{service: service, authority: authority, operations: map[string]*labRecoveryOperation{}}, nil
}

func (s *LabService) RecoveryBackend() LabRecoveryBackend {
	if s == nil || s.core == nil {
		return nil
	}
	s.core.mu.Lock()
	defer s.core.mu.Unlock()
	if s.core.closed || s.core.closing || s.core.recovery == nil || s.core.recovery.closed {
		return nil
	}
	return &labRecoveryBackend{service: s}
}

func (b *labRecoveryBackend) coordinator() (*labRecoveryCoordinator, error) {
	if b == nil || b.service == nil || b.service.core == nil {
		return nil, labServiceError(LabBackendUnavailable, false)
	}
	c := b.service.core.recovery
	if c == nil {
		return nil, labServiceError(LabBackendUnavailable, false)
	}
	return c, nil
}

func (b *labRecoveryBackend) Scope() authz.ResourceScope {
	if b == nil || b.service == nil {
		return authz.ResourceScope{}
	}
	return b.service.Scope()
}

func (b *labRecoveryBackend) Create(ctx context.Context, headers []string, request LabRecoveryCreateRequest) (LabRecoveryView, error) {
	c, err := b.coordinator()
	if err != nil {
		return LabRecoveryView{}, err
	}
	return c.create(ctx, headers, request)
}

func (b *labRecoveryBackend) Inspect(ctx context.Context, headers []string, id string) (LabRecoveryView, error) {
	c, err := b.coordinator()
	if err != nil {
		return LabRecoveryView{}, err
	}
	return c.inspect(ctx, headers, id)
}

func (b *labRecoveryBackend) Approve(ctx context.Context, headers []string, id string, request LabRecoveryApprovalRequest) (LabRecoveryView, error) {
	c, err := b.coordinator()
	if err != nil {
		return LabRecoveryView{}, err
	}
	return c.approve(ctx, headers, id, request)
}

func (b *labRecoveryBackend) Execute(ctx context.Context, headers []string, id string, request LabRecoveryExecuteRequest) (LabRecoveryView, error) {
	c, err := b.coordinator()
	if err != nil {
		return LabRecoveryView{}, err
	}
	return c.execute(ctx, headers, id, request)
}

func (b *labRecoveryBackend) Revoke(ctx context.Context, headers []string, id string, request LabRecoveryRevokeRequest) (LabRecoveryView, error) {
	c, err := b.coordinator()
	if err != nil {
		return LabRecoveryView{}, err
	}
	return c.revoke(ctx, headers, id, request)
}

func labRecoveryOperationID() (string, error) {
	id, err := labServiceID()
	if err != nil {
		return "", err
	}
	return "labrec_" + id[len("labop_"):], nil
}

func labRecoveryRequestValid(id, plan string, revision uint64) bool {
	return labRecoveryID.MatchString(id) && lifecycleNonzeroHash(plan) && revision != 0
}

func (c *labRecoveryCoordinator) operationLocked(id string) (*labRecoveryOperation, error) {
	if c == nil || c.closed || c.operations == nil || !labRecoveryID.MatchString(id) {
		return nil, labServiceError(LabBackendInvalid, false)
	}
	op := c.operations[id]
	if op == nil {
		return nil, labServiceError(LabBackendNotFound, false)
	}
	return op, nil
}

func labRecoveryTxnForID(w *lifecycleV3Wire, id string) (*lifecycleRecoveryTxn, bool) {
	if w == nil {
		return nil, false
	}
	if w.Recovery != nil && w.Recovery.Plan.RecoveryID == id {
		return w.Recovery, true
	}
	for n := len(w.RecoveryHistory) - 1; n >= 0; n-- {
		if w.RecoveryHistory[n].Plan.RecoveryID == id {
			return &w.RecoveryHistory[n], true
		}
	}
	return nil, false
}

// Caller holds the service mutex. The returned value contains detached public
// metadata only; owner material, authority refs and the raw WAL never escape.
func (c *labRecoveryCoordinator) viewLocked(op *labRecoveryOperation, replayed bool) (LabRecoveryView, error) {
	if c == nil || op == nil || op.store == nil || op.store.core == nil {
		return LabRecoveryView{}, labServiceError(LabBackendUnavailable, false)
	}
	x := op.store.core
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.verify() != nil || x.record.core == nil {
		return LabRecoveryView{}, labServiceError(LabBackendUnavailable, false)
	}
	w := x.record.core
	a, ok := labRecoveryTxnForID(w, op.id)
	if !ok {
		return LabRecoveryView{}, labServiceError(LabBackendNotFound, false)
	}
	head := w.Current.Head
	advanced := a.Phase == "COMPLETED" && a.Completion != nil
	if advanced {
		head = a.Completion.Head
	}
	blocked := w.Current.Active != nil && !lifecycleTerminal(w.Current.Active.Phase)
	if w.Recovery != nil && w.Recovery.Plan.RecoveryID == op.id && w.Recovery.Phase != "COMPLETED" && w.Recovery.Phase != "REVOKED_UNSTARTED" {
		blocked = true
	}
	var failure *LabRecoveryFailureView
	if (a.Phase == "RECOVERY_UNKNOWN" || a.Phase == "FAILED_RECONCILED") && a.Failure != nil {
		failure = &LabRecoveryFailureView{Schema: LabRecoveryFailureViewSchema, Code: a.Failure.Code,
			CleanupState: "PENDING", NextAction: "CLOSE_REQUIRED"}
		if op.failure != nil && op.failure.Schema == LabRecoveryFailureViewSchema && op.failure.Code == a.Failure.Code {
			copy := *op.failure
			failure = &copy
		}
	}
	return LabRecoveryView{Schema: LabRecoveryViewSchema, Boundary: LabBackendBoundary, RecoveryID: op.id,
		Phase: a.Phase, Revision: w.Revision, PlanSHA256: a.Plan.PlanSHA256,
		UnknownOperationID: a.Plan.UnknownOperationID, OriginalPlanSHA256: a.Plan.OriginalPlanSHA256,
		PreviousHeadSHA256: a.Plan.PreviousHeadSHA256, HeadSHA256: head.HeadSHA256, HeadGeneration: head.Generation,
		TargetArtifactRecordSHA256: a.Plan.TargetArtifact.RecordSHA256, TargetConfigSHA256: a.Plan.TargetArtifact.Config.SHA256,
		ExpiresAt: a.Plan.ExpiresAt, WriteBlocked: blocked, Replayed: replayed, HeadAdvanced: advanced, Failure: failure,
		Proof: LabProofView{}}, nil
}

func (c *labRecoveryCoordinator) inspect(ctx context.Context, headers []string, id string) (LabRecoveryView, error) {
	if c == nil || c.service == nil || c.service.core == nil || artifactContext(ctx) != nil {
		return LabRecoveryView{}, labServiceError(LabBackendUnavailable, false)
	}
	s := c.service.core
	s.mu.Lock()
	defer s.mu.Unlock()
	if c.closed || s.closed || s.closing {
		return LabRecoveryView{}, labServiceError(LabBackendUnavailable, false)
	}
	if err := c.authority.authorizeRead(headers, time.Now().UTC()); err != nil {
		return LabRecoveryView{}, labServiceAuthError(err)
	}
	op, err := c.operationLocked(id)
	if err != nil {
		return LabRecoveryView{}, err
	}
	return c.viewLocked(op, false)
}

func labRecoveryExactTarget(ctx context.Context, store *ArtifactStore, target ArtifactDescriptor) error {
	descriptor, artifact, source, err := labCollectorLoad(ctx, store, target.RecordSHA256)
	if err != nil || artifact == nil || !reflect.DeepEqual(descriptor, target) || !reflect.DeepEqual(artifact.Descriptor(), target.Config) {
		return errLifecycleUnsafe
	}
	role, err := labCollectorRole(source)
	if err != nil || role == "" {
		return errLifecycleUnsafe
	}
	return nil
}

func labRecoveryOwnerExpiry(store *lifecycleRecoveryStore, owner *lifecycleRecoveryOwnerToken, now time.Time) (time.Time, bool, error) {
	if store == nil || store.core == nil {
		return time.Time{}, false, errLifecycleUnsafe
	}
	x := store.core
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.verify() != nil || x.record.core == nil || x.record.core.RecoveryOwner == nil || owner == nil || owner.core == nil ||
		x.live != owner.core || owner.core.store != x || owner.core.nonce != x.record.core.RecoveryOwner.OwnerNonce || owner.core.fence != x.record.core.RecoveryOwner.Fence {
		return time.Time{}, false, errLifecycleUnsafe
	}
	expires := x.record.core.RecoveryOwner.ExpiresAt
	return expires, now.Before(expires), nil
}

func labRecoveryPlanExpiry(now time.Time, seconds uint16, ownerExpiry time.Time) (time.Time, error) {
	expires := now.Add(time.Duration(seconds) * time.Second)
	if ownerExpiry.Before(expires) {
		expires = ownerExpiry
	}
	if !expires.After(now) {
		return time.Time{}, errLifecycleUnsafe
	}
	return expires, nil
}

// A revoked first recovery still owns the evolved V3 store, but it never
// created an ordinary current-epoch facade. Select the plan schema from the
// actual epoch lineage: the embedded, fully validated V2 source is the only
// legal v1 source while no epoch has been retired. Later epochs require the
// source-root-bound v2 constructor and cannot be downgraded to bypass its
// current-owner checks.
func labRecoveryPlanForCurrentEpoch(source lifecycleV3Record, recoveryID, initiator string, target ArtifactDescriptor, now, expires time.Time) (labRecoveryPlan, error) {
	if source.core == nil {
		return labRecoveryPlan{}, errLifecycleUnsafe
	}
	if len(source.core.RetiredEpochs) != 0 {
		return newLabRecoveryPlanV2(source, recoveryID, initiator, target, now, expires)
	}
	original, err := decodeLifecycleRecord(source.core.SourceV2.ControlBytes)
	if err != nil || original.wire == nil || source.core.SourceV2.Schema != lifecycleSchemaV2 ||
		source.core.SourceV2.ControlSHA256 != labConfigHash(source.core.SourceV2.ControlBytes) ||
		original.wire.RecordSHA256 != source.core.SourceV2.RecordSHA256 || original.wire.Revision != source.core.SourceV2.Revision {
		return labRecoveryPlan{}, errLifecycleUnsafe
	}
	return newLabRecoveryPlan(original, recoveryID, initiator, target, now, expires)
}

func (c *labRecoveryCoordinator) create(ctx context.Context, headers []string, request LabRecoveryCreateRequest) (LabRecoveryView, error) {
	if c == nil || c.service == nil || c.service.core == nil || artifactContext(ctx) != nil || !labServiceValidID(request.UnknownOperationID) ||
		!lifecycleNonzeroHash(request.OriginalPlanSHA256) || request.Revision == 0 || request.TTLSeconds < 1 || request.TTLSeconds > 300 {
		return LabRecoveryView{}, labServiceError(LabBackendInvalid, false)
	}
	s := c.service.core
	s.mu.Lock()
	defer s.mu.Unlock()
	if c.closed || s.closed || s.closing || s.busy || c.activeID != "" || len(c.operations) >= labServiceOperationLimit ||
		s.runtime == nil || s.kernel == nil || s.artifacts == nil {
		return LabRecoveryView{}, labServiceError(LabBackendConflict, false)
	}
	now := time.Now().UTC()
	initiator, err := c.authority.captureInitiator(headers, now)
	if err != nil {
		return LabRecoveryView{}, labServiceAuthError(err)
	}
	defer c.authority.discardInitiator(initiator)
	actor, err := c.authority.initiatorReference(initiator)
	if err != nil {
		return LabRecoveryView{}, labServiceAuthError(err)
	}
	id, err := labRecoveryOperationID()
	if err != nil {
		return LabRecoveryView{}, labServiceError(LabBackendUnavailable, false)
	}

	source, present, err := s.runtime.recoverySnapshot()
	if err != nil {
		return LabRecoveryView{}, labServiceError(LabBackendUnavailable, false)
	}
	var plan labRecoveryPlan
	var store *lifecycleRecoveryStore
	var owner *lifecycleRecoveryOwnerToken
	var sourceCleanup *labRecoveryCleanupCustody
	var sourceReentry *labRecoveryTerminalReentryPermit
	if !present {
		original, wireErr := s.wire()
		if wireErr != nil || original.wire == nil || original.wire.Active == nil || original.wire.Active.Phase != "UNKNOWN" || original.wire.Active.Intent == nil ||
			original.wire.Active.Plan.OperationID != request.UnknownOperationID || original.wire.Active.Plan.PlanSHA256 != request.OriginalPlanSHA256 || original.wire.Revision != request.Revision {
			return LabRecoveryView{}, labServiceError(LabBackendConflict, false)
		}
		target := cloneArtifactDescriptor(original.wire.Active.Plan.Artifact)
		if labRecoveryExactTarget(ctx, s.artifacts, target) != nil {
			return LabRecoveryView{}, labServiceError(LabBackendUnavailable, false)
		}
		plan, err = newLabRecoveryPlan(original, id, actor, target, now, now.Add(time.Duration(request.TTLSeconds)*time.Second))
		if err != nil {
			return LabRecoveryView{}, labServiceError(LabBackendUnavailable, false)
		}
		s.ready = false
		store, err = s.runtime.evolveForRecovery(&plan, time.Now().UTC())
		if err != nil {
			return LabRecoveryView{}, labServiceError(LabBackendUnavailable, true)
		}
		issuedAt := time.Now().UTC()
		owner, err = store.acquireRecoveryOwner(issuedAt, issuedAt.Add(5*time.Minute))
		if err != nil {
			return LabRecoveryView{}, labServiceError(LabBackendUnavailable, true)
		}
		c.store, c.owner = store, owner
		x := store.core
		x.mu.Lock()
		revision, digest := x.record.core.Revision, x.record.core.RecordSHA256
		x.mu.Unlock()
		if err := store.beginRecovery(owner, &plan, revision, digest, time.Now().UTC()); err != nil {
			return LabRecoveryView{}, labServiceError(LabBackendUnavailable, true)
		}
		s.store, s.owner = nil, nil
	} else {
		var terminal *labRecoveryOperation
		for _, candidate := range c.operations {
			if candidate != nil && candidate.settled && candidate.reentry != nil && candidate.reentry.core != nil && !candidate.reentry.core.used &&
				(candidate.cleanup != nil || candidate.sourceCleanup != nil || candidate.reentry.core.cleanupSHA == "") &&
				candidate.plan.UnknownOperationID == request.UnknownOperationID && candidate.plan.OriginalPlanSHA256 == request.OriginalPlanSHA256 {
				if terminal != nil {
					return LabRecoveryView{}, labServiceError(LabBackendConflict, false)
				}
				terminal = candidate
			}
		}
		if terminal != nil {
			terminalCleanup := terminal.cleanup
			if terminalCleanup == nil {
				terminalCleanup = terminal.sourceCleanup
			}
			terminalTxn, ok := labRecoveryTxnForID(source.core, terminal.id)
			if !ok || (terminalTxn.Phase != "FAILED_RECONCILED" && terminalTxn.Phase != "REVOKED_UNSTARTED") ||
				(terminalTxn.Phase == "FAILED_RECONCILED" && terminalTxn.Failure == nil) ||
				source.core.Revision != request.Revision || s.runtime.core == nil || s.runtime.core.recovery == nil ||
				s.runtime.core.current != nil || s.store != nil {
				return LabRecoveryView{}, labServiceError(LabBackendConflict, false)
			}
			store = s.runtime.core.recovery
			owner = c.owner
			reuseOwner := owner != nil && owner.core != nil && terminal.reentry.core != nil &&
				owner.core.store == store.core && owner.core.fence == terminal.reentry.core.fence+1
			if reuseOwner {
				if _, fresh, ownerErr := labRecoveryOwnerExpiry(store, owner, now); ownerErr != nil || !fresh {
					return LabRecoveryView{}, labServiceError(LabBackendUnavailable, false)
				}
			} else {
				owner, err = store.acquireRecoveryOwner(now, now.Add(5*time.Minute))
				if err != nil {
					return LabRecoveryView{}, labServiceError(LabBackendUnavailable, true)
				}
				// Preserve the actual new token even if a later source/target check
				// rejects this Create; a retry must reuse, never mint fence+2.
				c.owner = owner
			}
			expires, _, ownerErr := labRecoveryOwnerExpiry(store, owner, time.Now().UTC())
			if ownerErr != nil {
				return LabRecoveryView{}, labServiceError(LabBackendUnavailable, true)
			}
			now = time.Now().UTC()
			planExpires, expiryErr := labRecoveryPlanExpiry(now, request.TTLSeconds, expires)
			if expiryErr != nil {
				return LabRecoveryView{}, labServiceError(LabBackendConflict, false)
			}
			target := cloneArtifactDescriptor(terminal.plan.TargetArtifact)
			if labRecoveryExactTarget(ctx, s.artifacts, target) != nil {
				return LabRecoveryView{}, labServiceError(LabBackendUnavailable, false)
			}
			if terminalCleanup != nil {
				plan, err = newLabRecoveryPlanV3(owner, terminal.reentry, id, actor, target, now, planExpires)
			} else {
				plan, err = newLabRecoveryPlanV2Reentry(owner, terminal.reentry, id, actor, target, now, planExpires)
			}
			if err != nil {
				return LabRecoveryView{}, labServiceError(LabBackendUnavailable, true)
			}
			x := store.core
			x.mu.Lock()
			revision, digest := x.record.core.Revision, x.record.core.RecordSHA256
			x.mu.Unlock()
			if err = store.beginRecovery(owner, &plan, revision, digest, time.Now().UTC()); err != nil {
				return LabRecoveryView{}, labServiceError(LabBackendUnavailable, true)
			}
			sourceCleanup, sourceReentry = terminalCleanup, terminal.reentry
			s.ready = false
		} else if source.core == nil || source.core.Current.Active == nil || source.core.Current.Active.Phase != "UNKNOWN" || source.core.Current.Active.Intent == nil ||
			source.core.Current.Active.Plan.OperationID != request.UnknownOperationID || source.core.Current.Active.Plan.PlanSHA256 != request.OriginalPlanSHA256 || source.core.Revision != request.Revision ||
			s.runtime.core == nil || s.runtime.core.recovery == nil || s.runtime.core.current != s.store {
			return LabRecoveryView{}, labServiceError(LabBackendConflict, false)
		} else {
		store, owner = s.runtime.core.recovery, c.owner
		_, fresh, ownerErr := labRecoveryOwnerExpiry(store, owner, now)
		if ownerErr != nil || !fresh {
			// Replacement is permitted only after the exact old token is observed
			// expired under this same live store. acquireRecoveryOwner performs the
			// durable fence increment and installs the sole new process token.
			if ownerErr != nil {
				return LabRecoveryView{}, labServiceError(LabBackendUnavailable, false)
			}
			owner, err = store.acquireRecoveryOwner(now, now.Add(5*time.Minute))
			if err != nil {
				return LabRecoveryView{}, labServiceError(LabBackendUnavailable, true)
			}
			c.owner = owner
			source, present, err = s.runtime.recoverySnapshot()
			if err != nil || !present || source.core == nil || source.core.Current.Active == nil || source.core.Current.Active.Phase != "UNKNOWN" ||
				source.core.Current.Active.Plan.OperationID != request.UnknownOperationID || source.core.Current.Active.Plan.PlanSHA256 != request.OriginalPlanSHA256 {
				return LabRecoveryView{}, labServiceError(LabBackendUnavailable, true)
			}
		}
		expires, _, ownerErr := labRecoveryOwnerExpiry(store, owner, time.Now().UTC())
		if ownerErr != nil {
			return LabRecoveryView{}, labServiceError(LabBackendUnavailable, true)
		}
		now = time.Now().UTC()
		planExpires, expiryErr := labRecoveryPlanExpiry(now, request.TTLSeconds, expires)
		if expiryErr != nil {
			return LabRecoveryView{}, labServiceError(LabBackendConflict, false)
		}
		target := cloneArtifactDescriptor(source.core.Current.Active.Plan.Artifact)
		if labRecoveryExactTarget(ctx, s.artifacts, target) != nil {
			return LabRecoveryView{}, labServiceError(LabBackendUnavailable, false)
		}
			plan, err = labRecoveryPlanForCurrentEpoch(source, id, actor, target, now, planExpires)
		if err != nil {
			return LabRecoveryView{}, labServiceError(LabBackendUnavailable, false)
		}
		s.ready = false
			if s.store == nil {
				err = s.runtime.beginRecoveryWithoutCurrent(store, owner, &plan, source.core.Revision, source.core.RecordSHA256, time.Now().UTC())
			} else {
				err = s.runtime.beginNextRecovery(s.store, store, owner, &plan, source.core.Revision, source.core.RecordSHA256, time.Now().UTC())
			}
			if err != nil {
			return LabRecoveryView{}, labServiceError(LabBackendUnavailable, true)
		}
		s.store, s.owner = nil, nil
		}
	}
	session, err := c.authority.bindPlan(initiator, store, owner, time.Now().UTC())
	if err != nil {
		return LabRecoveryView{}, labServiceError(LabBackendUnavailable, true)
	}
	op := &labRecoveryOperation{id: id, session: session, store: store, owner: owner, plan: plan.descriptor(),
		sourceCleanup: sourceCleanup, sourceReentry: sourceReentry}
	c.store, c.owner, c.operations[id], c.activeID = store, owner, op, id
	return c.viewLocked(op, false)
}

func (c *labRecoveryCoordinator) approve(ctx context.Context, headers []string, id string, request LabRecoveryApprovalRequest) (LabRecoveryView, error) {
	if c == nil || c.service == nil || c.service.core == nil || artifactContext(ctx) != nil || !labRecoveryRequestValid(id, request.PlanSHA256, request.Revision) {
		return LabRecoveryView{}, labServiceError(LabBackendInvalid, false)
	}
	s := c.service.core
	s.mu.Lock()
	defer s.mu.Unlock()
	op, err := c.operationLocked(id)
	if err != nil {
		return LabRecoveryView{}, err
	}
	v, err := c.viewLocked(op, false)
	if err != nil || c.activeID != id || s.busy || v.Phase != "PLANNED" || v.PlanSHA256 != request.PlanSHA256 || v.Revision != request.Revision {
		return LabRecoveryView{}, labServiceError(LabBackendConflict, false)
	}
	now := time.Now().UTC()
	approval, err := c.authority.approve(headers, op.session, now)
	if err != nil {
		return LabRecoveryView{}, labServiceAuthError(err)
	}
	if err := op.store.recordRecoveryApproval(op.owner, approval, now); err != nil {
		return LabRecoveryView{}, labServiceError(LabBackendUnavailable, true)
	}
	return c.viewLocked(op, false)
}

func (c *labRecoveryCoordinator) revoke(ctx context.Context, headers []string, id string, request LabRecoveryRevokeRequest) (LabRecoveryView, error) {
	if c == nil || c.service == nil || c.service.core == nil || artifactContext(ctx) != nil || !labRecoveryRequestValid(id, request.PlanSHA256, request.Revision) ||
		(request.Reason != "OPERATOR_REQUESTED" && request.Reason != "SAFETY_STOP") {
		return LabRecoveryView{}, labServiceError(LabBackendInvalid, false)
	}
	s := c.service.core
	s.mu.Lock()
	defer s.mu.Unlock()
	op, err := c.operationLocked(id)
	if err != nil {
		return LabRecoveryView{}, err
	}
	v, err := c.viewLocked(op, false)
	if err != nil || c.activeID != id || s.busy || op.executing || v.PlanSHA256 != request.PlanSHA256 || v.Revision != request.Revision || (v.Phase != "PLANNED" && v.Phase != "APPROVED") {
		return LabRecoveryView{}, labServiceError(LabBackendConflict, false)
	}
	now := time.Now().UTC()
	check, err := c.authority.authorizeRevoke(headers, op.store, op.owner, op.session, now)
	if err != nil {
		return LabRecoveryView{}, labServiceAuthError(err)
	}
	if check.core == nil || op.store.revokeRecovery(op.owner, check.core.actorRef, "EXPLICIT_REVOKED", now) != nil {
		return LabRecoveryView{}, labServiceError(LabBackendUnavailable, true)
	}
	var reentry *labRecoveryTerminalReentryPermit
	if op.plan.Schema == labRecoveryPlanSchemaV3 && op.plan.StartMode == labRecoveryStartModeOldEpochAbsent {
		absent, custodyErr := c.newAbsentReentryCustodyLocked(op)
		if custodyErr != nil {
			return LabRecoveryView{}, labServiceError(LabBackendUnavailable, true)
		}
		reentry, err = op.store.recordRecoveryAbsentReentry(op.owner, absent, time.Now().UTC())
	} else {
		live, custodyErr := c.newLiveReentryCustodyLocked(op)
		if custodyErr != nil {
			return LabRecoveryView{}, labServiceError(LabBackendUnavailable, true)
		}
		reentry, err = live.consumeRecoveryLiveReentry(s.runtime, op.store, op.owner, time.Now().UTC())
	}
	if err != nil || reentry == nil {
		return LabRecoveryView{}, labServiceError(LabBackendUnavailable, true)
	}
	op.reentry = reentry
	op.settled, c.activeID = true, ""
	if err := c.authority.retireSession(op.session); err != nil {
		return LabRecoveryView{}, labServiceError(LabBackendUnavailable, true)
	}
	return c.viewLocked(op, false)
}

// Caller holds the exact service mutex. This captures only the retained live
// owned epoch after durable unstarted revocation; it does not stop or restart
// the kernel and it cannot be reconstructed from the terminal WAL.
func (c *labRecoveryCoordinator) newLiveReentryCustodyLocked(op *labRecoveryOperation) (*labRecoveryLiveReentryCustody, error) {
	if c == nil || c.service == nil || c.service.core == nil || op == nil || op.store == nil || op.store.core == nil ||
		op.owner == nil || op.owner.core == nil {
		return nil, errLifecycleUnsafe
	}
	s := c.service.core
	if s.runtime == nil || s.runtime.core == nil || s.kernel == nil || s.kernel.ownedLabKernelCore == nil ||
		s.runtime.core.recovery != op.store || !lifecycleRecoverySameDisk(s.runtime.core.disk, op.store.core.disk) {
		return nil, errLifecycleUnsafe
	}
	identity, err := s.kernel.identity()
	if err != nil || !labQuiescenceIdentityValid(identity) {
		return nil, errLifecycleUnsafe
	}
	custody := &labRecoveryLiveReentryCustody{issuer: &processLabRecoveryLiveReentryIssuer, service: s,
		runtime: s.runtime.core, store: op.store.core, disk: s.runtime.core.disk, owner: op.owner.core,
		kernel: s.kernel.ownedLabKernelCore, identity: identity, recoveryID: op.id}
	service, runtime, store, disk, owner, kernel, sealedIdentity, recoveryID := s, s.runtime.core, op.store.core, s.runtime.core.disk, op.owner.core, s.kernel.ownedLabKernelCore, identity, op.id
	custody.binding = func(candidate *labRecoveryLiveReentryCustody) bool {
		return candidate == custody && candidate.service == service && candidate.runtime == runtime && candidate.store == store &&
			candidate.disk == disk && candidate.owner == owner && candidate.kernel == kernel && candidate.identity == sealedIdentity && candidate.recoveryID == recoveryID
	}
	if !custody.issuer.issue(custody) {
		return nil, errLifecycleUnsafe
	}
	return custody, nil
}

func (c *labRecoveryCoordinator) newAbsentReentryCustodyLocked(op *labRecoveryOperation) (*labRecoveryAbsentReentryCustody, error) {
	if c == nil || c.service == nil || c.service.core == nil || op == nil || op.store == nil || op.store.core == nil ||
		op.owner == nil || op.owner.core == nil || op.sourceCleanup == nil || op.sourceReentry == nil || op.sourceReentry.core == nil ||
		op.plan.Schema != labRecoveryPlanSchemaV3 || op.plan.StartMode != labRecoveryStartModeOldEpochAbsent {
		return nil, errLifecycleUnsafe
	}
	s, source, reentry := c.service.core, op.sourceCleanup, op.sourceReentry.core
	if s.runtime == nil || s.runtime.core == nil || s.runtime.core.recovery != op.store ||
		!lifecycleRecoverySameDisk(s.runtime.core.disk, op.store.core.disk) || source.old == nil ||
		!labQuiescenceIdentityValid(source.oldIdentity) || !labQuiescenceExitDrained(source.oldExit) ||
		reentry.runtime != s.runtime.core || reentry.service != s || reentry.store != op.store.core ||
		!lifecycleRecoverySameDisk(reentry.disk, s.runtime.core.disk) || !lifecycleNonzeroHash(reentry.cleanupSHA) ||
		!lifecycleNonzeroHash(reentry.terminalRoot) || len(reentry.terminalCanonical) == 0 {
		return nil, errLifecycleUnsafe
	}
	custody := &labRecoveryAbsentReentryCustody{issuer: &processLabRecoveryAbsentReentryIssuer, operation: op,
		service: s, runtime: s.runtime.core, store: op.store.core, disk: s.runtime.core.disk, owner: op.owner.core,
		reentry: reentry, sourceCleanup: source, oldIdentity: source.oldIdentity, cleanupSHA: reentry.cleanupSHA,
		terminalRoot: reentry.terminalRoot, terminalCanonical: reentry.terminalCanonical,
		planSHA: op.plan.PlanSHA256, recoveryID: op.id}
	operation, service, runtime, store, disk, owner, sourceReentry, sourceCleanup := op, s, s.runtime.core, op.store.core, s.runtime.core.disk, op.owner.core, reentry, source
	oldIdentity, cleanupSHA, terminalRoot, terminalCanonical, planSHA, recoveryID := custody.oldIdentity, custody.cleanupSHA, custody.terminalRoot, custody.terminalCanonical, custody.planSHA, custody.recoveryID
	custody.binding = func(candidate *labRecoveryAbsentReentryCustody) bool {
		return candidate == custody && candidate.operation == operation && candidate.service == service && candidate.runtime == runtime &&
			candidate.store == store && candidate.disk == disk && candidate.owner == owner && candidate.reentry == sourceReentry &&
			candidate.sourceCleanup == sourceCleanup && candidate.oldIdentity == oldIdentity && candidate.cleanupSHA == cleanupSHA &&
			candidate.terminalRoot == terminalRoot && candidate.terminalCanonical == terminalCanonical && candidate.planSHA == planSHA && candidate.recoveryID == recoveryID
	}
	if !custody.issuer.issue(custody) {
		return nil, errLifecycleUnsafe
	}
	return custody, nil
}

func (c *labRecoveryCoordinator) execute(ctx context.Context, headers []string, id string, request LabRecoveryExecuteRequest) (LabRecoveryView, error) {
	if c == nil || c.service == nil || c.service.core == nil || artifactContext(ctx) != nil || !labRecoveryRequestValid(id, request.PlanSHA256, request.Revision) {
		return LabRecoveryView{}, labServiceError(LabBackendInvalid, false)
	}
	s := c.service.core
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	s.mu.Lock()
	op, err := c.operationLocked(id)
	if err != nil {
		s.mu.Unlock()
		return LabRecoveryView{}, err
	}
	copiedHeaders := append([]string(nil), headers...)
	if op.cleanup != nil {
		// The source-owned cleanup custody identifies the warm reconciliation
		// path without observing its public phase, busy/executing state or retry
		// budget. Fresh same-initiator Prepare authorization is deliberately
		// before all of those state responses and before any mutation. A missing,
		// foreign, revoked or stale caller cannot observe or spend the source
		// owner's sole explicit retry.
		session, custody := op.session, op.cleanup
		s.mu.Unlock()
		precheck, authErr := c.authority.authorizeReconcile(copiedHeaders, session, time.Now().UTC())
		if authErr != nil {
			return LabRecoveryView{}, labServiceAuthError(authErr)
		}
		s.mu.Lock()
		current, currentErr := c.operationLocked(id)
		currentView, currentViewErr := c.viewLocked(op, false)
		if currentErr != nil || current != op || currentViewErr != nil || c.closed || s.closed || s.closing ||
			s.busy || op.executing || op.settled || c.activeID != id || op.cleanup != custody ||
			!op.reconciliationRetryable() || currentView.Phase != "RECOVERY_UNKNOWN" || !op.physical ||
			op.failureCode == "" || !op.failureRecorded || currentView.PlanSHA256 != request.PlanSHA256 ||
			currentView.Revision != request.Revision || !op.reconciliationCheckCurrent(precheck) {
			s.mu.Unlock()
			return LabRecoveryView{}, labServiceError(LabBackendConflict, false)
		}
		op.executing, s.busy = true, true
		s.mu.Unlock()
		reconcileErr := c.retryPlatformReconciliation(copiedHeaders, precheck, op)
		s.mu.Lock()
		s.busy, op.executing = false, false
		committed := reconcileErr == nil && op.reconcileState == labRecoveryReconcileCommitted && op.reentry != nil
		locked := op.reconcileState == labRecoveryReconcileLocked
		if committed {
			op.settled, c.activeID, s.ready = true, "", false
			if retireErr := c.authority.retireSession(op.session); retireErr != nil {
				reconcileErr = retireErr
			}
		} else if locked {
			if op.failure != nil {
				op.failure.CleanupState = "UNCERTAIN"
				op.failure.NextAction = "CLOSE_REQUIRED"
			}
			op.settled, c.activeID, s.ready = true, "", false
			if retireErr := c.authority.retireSession(op.session); retireErr != nil {
				reconcileErr = retireErr
			}
		}
		result, resultErr := c.viewLocked(op, false)
		s.mu.Unlock()
		if reconcileErr != nil {
			return LabRecoveryView{}, labServiceError(LabBackendUnavailable, true)
		}
		if resultErr != nil {
			return LabRecoveryView{}, resultErr
		}
		return result, nil
	}
	v, viewErr := c.viewLocked(op, false)
	normalExecute := !op.settled && v.Phase == "APPROVED"
	if viewErr != nil || c.closed || s.closed || s.closing || s.busy || op.executing || op.settled || c.activeID != id ||
		!normalExecute || v.PlanSHA256 != request.PlanSHA256 || v.Revision != request.Revision {
		s.mu.Unlock()
		return LabRecoveryView{}, labServiceError(LabBackendConflict, false)
	}
	op.executing, s.busy = true, true
	ownedCtx := s.ctx
	s.mu.Unlock()

	// The service lifetime, not the HTTP cancellation, owns physical cleanup.
	result, runErr := c.executePlatform(ownedCtx, copiedHeaders, op)
	s.mu.Lock()
	s.busy, op.executing = false, false
	if runErr == nil {
		op.settled, c.activeID = true, ""
		if retireErr := c.authority.retireSession(op.session); retireErr != nil {
			runErr = retireErr
		}
	} else if op.physical && op.failureCode != "" {
		// The durable transaction is already RECOVERY_UNKNOWN. Release the
		// service mutex while the closeMu-owned platform cleanup reaps the exact
		// owned kernel and saves its streams. No Start or authorization is replayed.
		s.mu.Unlock()
		failure := c.settlePlatformFailure(op, copiedHeaders)
		s.mu.Lock()
		op.failure = failure
		if op.reconcileState == labRecoveryReconcileCommitted && op.reentry != nil {
			op.settled, c.activeID, s.ready = true, "", false
			if retireErr := c.authority.retireSession(op.session); retireErr != nil {
				runErr = retireErr
			}
		} else if op.reconcileState != labRecoveryReconcileReady {
			// No source-owned retry exists, or an issued/possibly consumed core
			// capability made the result uncertain. Close is now the only exit.
			op.settled, c.activeID, s.ready = true, "", false
			if retireErr := c.authority.retireSession(op.session); retireErr != nil {
				runErr = retireErr
			}
		}
	} else if after, afterErr := c.viewLocked(op, false); afterErr == nil && after.Phase == "COMPLETED" {
		// Completion is already durable but the service facade rebind failed.
		// Never leave the spent authorization as an active operation and never
		// rewrite the completed WAL as UNKNOWN. The service remains not-ready and
		// its sole close owner retains the kernel/runtime for explicit Close.
		op.settled, c.activeID, s.ready = true, "", false
		if retireErr := c.authority.retireSession(op.session); retireErr != nil {
			runErr = retireErr
		}
	}
	s.mu.Unlock()
	if runErr != nil {
		return LabRecoveryView{}, labServiceError(LabBackendUnavailable, true)
	}
	return result, nil
}

func (a *labRecoveryAuthority) retireSession(h *labRecoverySession) error {
	if a == nil || a.core == nil || a.core.base == nil || a.core.base.core == nil || h == nil || h.core == nil {
		return labAuthorityFailure("session_invalid")
	}
	c, b := a.core, a.core.base.core
	b.mu.Lock()
	defer b.mu.Unlock()
	if c.closed || b.closed || b.poisoned || c.sessions[h] != h.core || h.core.authority != c {
		return labAuthorityFailure("session_invalid")
	}
	delete(c.sessions, h)
	h.core = nil
	return nil
}

func (c *labRecoveryCoordinator) close() error {
	if c == nil || c.closed {
		return nil
	}
	c.closed = true
	for _, op := range c.operations {
		if op != nil && op.cleanup != nil && op.cleanup.issuer != nil {
			custody, issuer := op.cleanup, op.cleanup.issuer
			if issuer.discard(custody, op) {
				op.cleanup = nil
			} else if issuer.contains(custody) {
				c.closed = false
				return errLifecycleUnsafe
			}
		}
	}
	for _, op := range c.operations {
		if op != nil && op.session != nil && op.session.core != nil {
			_ = c.authority.retireSession(op.session)
		}
	}
	c.operations = nil
	return c.authority.close()
}
