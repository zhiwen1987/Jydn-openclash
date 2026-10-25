//go:build linux && chengwang_mihomo_service && chengwang_mihomo_faults && chengwang_mihomo_recovery_native

package mihomodeploy

// This acceptance-only same-package coordinator joins existing actual private
// capabilities. It is not a product HTTP route, S2 verifier or completion API.
// No MODEL issuer, caller PID, serialized cap, seed WAL or trust bool is used.
import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"reflect"
	"strconv"
	"sync"
	"syscall"
	"time"
)

const labNativeRecoveryPrivate = "/tmp/chengwang-mihomo-recovery-private"
const labNativeRecoveryScope = "ACTUAL_OWNED_KERNEL_RECOVERY_STARTED_RECORD_NOT_HTTP_COMPLETION_OR_PRODUCTION"

// Cleanup observes the fixed kernel and fixture endpoints after their actual
// retained owners have closed them. This acceptance-only allowlist is separate
// from the two-port quiescence probe; it grants no stop or recovery authority.
func labNativeRecoveryCleanupDial(ctx context.Context, port uint16) labQuiescenceProbe {
	value := labQuiescenceProbe{Port: port, Result: "OTHER"}
	switch port {
	case 28411, 28412, 28413, 28414, 28415:
	default:
		return value
	}
	if artifactContext(ctx) != nil {
		value.Result = "CONTEXT_REJECTED"
		return value
	}
	dialer := net.Dialer{Timeout: 250 * time.Millisecond}
	value.Attempted = true
	conn, err := dialer.DialContext(ctx, "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil && conn != nil {
		value.Result = "CONNECTION_ACCEPTED"
	} else if errors.Is(err, syscall.ECONNREFUSED) {
		value.Result = "CONNECTION_REFUSED"
	} else if ctx.Err() != nil || errors.Is(err, context.Canceled) {
		value.Result = "CONTEXT_REJECTED"
	} else {
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			value.Result = "TIMEOUT"
		}
	}
	return value
}

var errLabNativeRecovery = errors.New("isolated native recovery experiment rejected")

// Closed diagnostic sentinels carry no original error text or credentials.
// They classify the first failed source step, never grant any authority.
var errLabNativeRecoveryBindPlan = errors.New("isolated native recovery bind rejected")
var errLabNativeRecoverySelfApproval = errors.New("isolated native recovery self approval accepted")
var errLabNativeRecoveryIndependentApproval = errors.New("isolated native recovery independent approval rejected")
var errLabNativeRecoveryApprovalFreshness = errors.New("isolated native recovery approval freshness rejected")
var errLabNativeRecoveryRecordApproval = errors.New("isolated native recovery approval record rejected")
var errLabNativeRecoveryApprovedReadback = errors.New("isolated native recovery approved readback rejected")

func labNativeRecoveryFailureCode(err error) string {
	switch err {
	case errLabNativeRecoveryBindPlan:
		return "NATIVE_BIND_PLAN_REJECTED"
	case errLabNativeRecoverySelfApproval:
		return "NATIVE_SELF_APPROVAL_ACCEPTED"
	case errLabNativeRecoveryIndependentApproval:
		return "NATIVE_INDEPENDENT_APPROVAL_REJECTED"
	case errLabNativeRecoveryApprovalFreshness:
		return "NATIVE_APPROVAL_FRESHNESS_REJECTED"
	case errLabNativeRecoveryRecordApproval:
		return "NATIVE_RECORD_APPROVAL_REJECTED"
	case errLabNativeRecoveryApprovedReadback:
		return "NATIVE_APPROVED_READBACK_REJECTED"
	default:
		return "NATIVE_RECOVERY"
	}
}

type labNativeRecoveryCheckpoint struct {
	Stage         string `json:"stage"`
	ControlSHA256 string `json:"controlSHA256"`
	RecordSHA256  string `json:"recordSHA256"`
	Revision      uint64 `json:"revision"`
	Phase         string `json:"phase"`
}

type labNativeRecoveryRunner struct {
	mu                 sync.Mutex
	service            *LabService
	authority          *labRecoveryAuthority
	store              *lifecycleRecoveryStore
	owner              *lifecycleRecoveryOwnerToken
	session            *labRecoverySession
	permit             *labRecoveryStartPermit
	started            *labRecoveryStartedEpoch
	old                *ownedLabKernel
	next               *ownedLabKernel
	legacy             []byte
	oldIdentity        labKernelIdentity
	newIdentity        labKernelIdentity
	quiescence         labQuiescenceObservation
	start              labRecoveryStartObservation
	newExit            *labKernelExit
	stages             []labNativeRecoveryCheckpoint
	claimed            bool
	holdsClose         bool
	cleanupDone        bool
	nextSettled        bool
	streamsSaved       bool
	selfApprovalDenied bool
	eventCheckpoints   []labNativeRecoveryEventCheckpoint
}

// Fixed-path exclusive private files. Raw WAL, streams and credentials never
// become public evidence here. The worker applies an explicit disclosure fence.
func labNativeRecoveryWrite(name string, raw []byte) error {
	allowed := false
	for _, n := range []string{"tokens.private.json", "native-report.private.json", "legacy-control.private.json",
		"planned-control.private.json", "approved-control.private.json", "stop-armed-control.private.json",
		"quiesced-control.private.json", "start-armed-control.private.json", "started-control.private.json",
		"verification-attempted-control.private.json", "verification-record.private.json",
		"reopened-control.private.json", "new-kernel.stdout", "new-kernel.stderr"} {
		if name == n {
			allowed = true
		}
	}
	if !allowed || len(raw) > maxLifecycleControlBytes || !labKernelPlain(labNativeRecoveryPrivate) {
		return errLabNativeRecovery
	}
	var st syscall.Stat_t
	if syscall.Lstat(labNativeRecoveryPrivate, &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFDIR ||
		st.Mode&07777 != 0700 || st.Uid != 10001 || st.Gid != 10001 {
		return errLabNativeRecovery
	}
	f, err := os.OpenFile(labNativeRecoveryPrivate+"/"+name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return errLabNativeRecovery
	}
	_, writeErr := f.Write(raw)
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return errLabNativeRecovery
	}
	d, err := os.Open(labNativeRecoveryPrivate)
	if err != nil {
		return errLabNativeRecovery
	}
	syncErr, closeErr = d.Sync(), d.Close()
	if syncErr != nil || closeErr != nil {
		return errLabNativeRecovery
	}
	return nil
}

func newLabNativeRecoveryRunner(s *LabService) (*labNativeRecoveryRunner, error) {
	if s == nil || s.core == nil || labServiceEnvelope() != nil {
		return nil, errLabNativeRecovery
	}
	c := s.core
	// Prevent service.Close racing ownership transfer. No store/auth mutex is
	// held across native I/O. Ordinary writes are independently blocked below.
	c.closeMu.Lock()
	c.mu.Lock()
	if !c.ready || c.closing || c.closed || c.busy || c.kernel == nil || c.runtime == nil || c.store == nil ||
		c.input == nil || c.artifacts == nil || c.authority == nil {
		c.mu.Unlock()
		c.closeMu.Unlock()
		return nil, errLabNativeRecovery
	}
	original, err := c.wire()
	if err != nil || original.wire.Active == nil || original.wire.Active.Phase != "UNKNOWN" || original.wire.Active.Attempt != 1 {
		c.mu.Unlock()
		c.closeMu.Unlock()
		return nil, errLabNativeRecovery
	}
	id, err := c.kernel.identity()
	if err != nil || !lifecycleRecoveryIdentityMatches(id, *original.wire.Head) {
		c.mu.Unlock()
		c.closeMu.Unlock()
		return nil, errLabNativeRecovery
	}
	a, err := newLabRecoveryAuthority(c.authority, time.Now().UTC())
	if err != nil {
		c.mu.Unlock()
		c.closeMu.Unlock()
		return nil, errLabNativeRecovery
	}
	raw, err := encodeLifecycleRecord(original)
	if err != nil {
		c.mu.Unlock()
		c.closeMu.Unlock()
		return nil, errLabNativeRecovery
	}
	c.ready, c.busy = false, true
	c.mu.Unlock()
	r := &labNativeRecoveryRunner{service: s, authority: a, old: c.kernel, legacy: bytes.Clone(raw),
		oldIdentity: id, holdsClose: true, stages: []labNativeRecoveryCheckpoint{}, eventCheckpoints: []labNativeRecoveryEventCheckpoint{}}
	if err := labNativeRecoveryWrite("legacy-control.private.json", raw); err != nil {
		// Return the retained owner even alongside failure: caller must cleanup.
		return r, err
	}
	return r, nil
}

func (r *labNativeRecoveryRunner) checkpoint(name string) error {
	if r == nil || r.store == nil || r.store.core == nil {
		return errLabNativeRecovery
	}
	x := r.store.core
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.verify() != nil {
		return errLabNativeRecovery
	}
	raw, exists, err := x.disk.readControl()
	if err != nil || !exists || !bytes.Equal(raw, x.raw) || x.disk.verify() != nil {
		return errLabNativeRecovery
	}
	decoded, err := decodeLifecycleV3Record(raw)
	if err != nil || !bytes.Equal(decoded.core.SourceV2.ControlBytes, r.legacy) {
		return errLabNativeRecovery
	}
	original, err := decodeLifecycleRecord(r.legacy)
	if err != nil || !reflect.DeepEqual(decoded.core.Current, lifecycleLegacyLedger(original, r.legacy)) || len(decoded.core.RetiredEpochs) != 0 {
		return errLabNativeRecovery
	}
	phase := ""
	if decoded.core.Recovery != nil {
		phase = decoded.core.Recovery.Phase
		if decoded.core.Recovery.Completion != nil {
			return errLabNativeRecovery
		}
	}
	if err := labNativeRecoveryWrite(name+"-control.private.json", raw); err != nil {
		return err
	}
	r.stages = append(r.stages, labNativeRecoveryCheckpoint{name, labConfigHash(raw), decoded.core.RecordSHA256, decoded.core.Revision, phase})
	return nil
}

func (r *labNativeRecoveryRunner) run(initiatorHeaders, approverHeaders, executorHeaders []string) error {
	if r == nil {
		return errLabNativeRecovery
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.claimed || !r.holdsClose || r.service == nil || r.authority == nil {
		return errLabNativeRecovery
	}
	r.claimed = true
	c := r.service.core
	now := time.Now().UTC()
	h, err := r.authority.captureInitiator(initiatorHeaders, now)
	if err != nil {
		return err
	}
	defer r.authority.discardInitiator(h)
	ref, err := r.authority.initiatorReference(h)
	if err != nil {
		return err
	}
	original, err := c.wire()
	if err != nil {
		return err
	}
	id, err := labServiceID()
	if err != nil {
		return err
	}
	plan, err := newLabRecoveryPlan(original, "labrec_"+id[len("labop_"):], ref, c.candidate, now, now.Add(2*time.Minute))
	if err != nil {
		return err
	}
	// Re-authenticate the initiator after preparation, before migration.
	fresh, err := r.authority.captureInitiator(initiatorHeaders, time.Now().UTC())
	if err != nil {
		return err
	}
	freshRef, err := r.authority.initiatorReference(fresh)
	r.authority.discardInitiator(fresh)
	if err != nil || freshRef != ref {
		return errLabNativeRecovery
	}
	r.store, err = c.runtime.evolveForRecovery(&plan, time.Now().UTC())
	if err != nil {
		return err
	}
	now = time.Now().UTC()
	r.owner, err = r.store.acquireRecoveryOwner(now, now.Add(2*time.Minute))
	if err != nil {
		return err
	}
	// Compare-and-swap source is the actual new owner revision, not the old
	// plan's original ExpectedRevision.
	x := r.store.core
	x.mu.Lock()
	revision, digest := x.record.core.Revision, x.record.core.RecordSHA256
	x.mu.Unlock()
	if err := r.store.beginRecovery(r.owner, &plan, revision, digest, time.Now().UTC()); err != nil {
		return err
	}
	if err := r.checkpoint("planned"); err != nil {
		return err
	}
	r.session, err = r.authority.bindPlan(h, r.store, r.owner, time.Now().UTC())
	if err != nil {
		return errLabNativeRecoveryBindPlan
	}
	// Actual current policy negative control on this same bound plan; it is
	// followed by positive independent approval, so an unrelated bad binding
	// cannot mask the self-approval check.
	if _, err := r.authority.approve(initiatorHeaders, r.session, time.Now().UTC()); err == nil {
		return errLabNativeRecoverySelfApproval
	}
	r.selfApprovalDenied = true
	// Approval issuance and its record are one logical transition: the
	// existing store contract requires IssuedAt.Equal(the supplied now).
	// Capture this real time once; never relax that private equality gate.
	approvalAt := time.Now().UTC()
	approval, err := r.authority.approve(approverHeaders, r.session, approvalAt)
	if err != nil {
		return errLabNativeRecoveryIndependentApproval
	}
	if !r.approvalStillCurrent(approval, approvalAt) {
		return errLabNativeRecoveryApprovalFreshness
	}
	if err := r.store.recordRecoveryApproval(r.owner, approval, approvalAt); err != nil {
		return errLabNativeRecoveryRecordApproval
	}
	if err := r.checkpoint("approved"); err != nil {
		return errLabNativeRecoveryApprovedReadback
	}
	binding, err := r.store.armRecoveryStop(r.owner, r.oldIdentity, time.Now().UTC())
	if err != nil {
		return err
	}
	if err := r.checkpoint("stop-armed"); err != nil {
		return err
	}
	if _, err := r.authority.authorizeStep(executorHeaders, r.session, "STOP", time.Now().UTC()); err != nil {
		return err
	}
	stopCtx, stopCancel := context.WithTimeout(c.ctx, time.Duration(plan.descriptor().Budgets.StopMillis)*time.Millisecond)
	q, observation, err := quiesceOwnedLabKernel(stopCtx, r.old, binding)
	stopCancel()
	r.quiescence = observation
	if err != nil {
		return err
	}
	if err := r.store.recordRecoveryQuiescence(r.owner, q, time.Now().UTC()); err != nil {
		return err
	}
	if err := r.checkpoint("quiesced"); err != nil {
		return err
	}
	r.permit, err = r.store.armRecoveryStart(r.owner, time.Now().UTC())
	if err != nil {
		return err
	}
	if err := r.checkpoint("start-armed"); err != nil {
		return err
	}
	if _, err := r.authority.authorizeStep(executorHeaders, r.session, "START", time.Now().UTC()); err != nil {
		return err
	}
	// c.ctx is the service lifetime, never the short preparation deadline.
	r.next, r.started, r.start, err = startOwnedRecoveryKernel(c.ctx, c.input, c.artifacts, r.permit)
	if err != nil {
		return err
	}
	if r.next == nil || r.started == nil || !r.start.StartInvoked || !r.start.StartReturned || r.start.Outcome != "STARTED" {
		return errLabNativeRecovery
	}
	r.newIdentity, err = r.next.identity()
	if err != nil || r.newIdentity == r.oldIdentity {
		return errLabNativeRecovery
	}
	if err := r.store.recordRecoveryStarted(r.owner, r.started, time.Now().UTC()); err != nil {
		return err
	}
	return r.checkpoint("started")
}

// Supplementary read-only freshness observation. It neither writes trusted
// time nor validates/authorizes a candidate or substitutes for the original
// record method and the subsequent current Stop/Start authorization gates.
func (r *labNativeRecoveryRunner) approvalStillCurrent(approval lifecycleRecoveryApproval, approvalAt time.Time) bool {
	if r == nil || r.service == nil || r.service.core == nil || r.store == nil || r.store.core == nil || r.owner == nil || r.owner.core == nil {
		return false
	}
	x := r.store.core
	x.mu.Lock()
	defer x.mu.Unlock()
	now := time.Now().UTC()
	if artifactContext(r.service.core.ctx) != nil || !lifecycleTime(now) || !lifecycleTime(approvalAt) ||
		!approval.IssuedAt.Equal(approvalAt) || now.Before(approvalAt) || !now.Before(approval.ExpiresAt) ||
		x.closed || x.poisoned || x.record.core == nil || x.live != r.owner.core || r.owner.core.store != x {
		return false
	}
	w := x.record.core
	o, a := w.RecoveryOwner, w.Recovery
	if o == nil || a == nil || a.Phase != "PLANNED" || a.Revocation != nil || a.Approval != nil || a.StopIntent != nil ||
		r.owner.core.nonce != o.OwnerNonce || r.owner.core.fence != o.Fence || o.Fence != w.LastRecoveryFence ||
		now.Before(w.LastTrustedAt) || approvalAt.Before(w.LastTrustedAt) || !now.Before(o.ExpiresAt) || !now.Before(a.Plan.ExpiresAt) ||
		approval.ExpiresAt.After(a.Plan.ExpiresAt) || approval.RecoveryPlanSHA256 != a.Plan.PlanSHA256 {
		return false
	}
	return artifactContext(r.service.core.ctx) == nil
}

// Replay proves rejection at the same original entrypoints. It never resets a
// registry, reconstructs a wrapper/core or mints fresh owner/permit material.
func (r *labNativeRecoveryRunner) rejectReplay() error {
	if r == nil || r.store == nil || r.next == nil || r.started == nil || r.permit == nil {
		return errLabNativeRecovery
	}
	if err := r.awaitNewKernelWait(); err != nil {
		return err
	}
	before := bytes.Clone(r.store.core.raw)
	calls, err := r.captureEvents("before-permit-cap-replay")
	if err != nil {
		return errLabNativeRecovery
	}
	c := r.service.core
	k, q, o, err := startOwnedRecoveryKernel(c.ctx, c.input, c.artifacts, r.permit)
	if err == nil || k != nil || q != nil || o.StartInvoked {
		return errLabNativeRecovery
	}
	if err := r.store.recordRecoveryStarted(r.owner, r.started, time.Now().UTC()); err == nil {
		return errLabNativeRecovery
	}
	after, err := r.captureEvents("after-permit-cap-replay")
	if err != nil || !reflect.DeepEqual(calls, after) || !bytes.Equal(before, r.store.core.raw) {
		return errLabNativeRecovery
	}
	return nil
}

// The original buffered startup-ready send precedes cmd.Wait's entry event.
// Synchronize only by bounded observation; never move ready/Wait, reset events,
// filter an event, consume a capability, or change authority/clock semantics.
func (r *labNativeRecoveryRunner) awaitNewKernelWait() error {
	if r == nil || r.next == nil || r.service == nil || r.service.core == nil {
		return errLabNativeRecovery
	}
	core, bounded := labNativeRecoveryReadCore(r.next)
	if !bounded {
		return errLabNativeRecovery
	}
	ctx, cancel := context.WithTimeout(r.service.core.ctx, 2*time.Second)
	defer cancel()
	for {
		events, bounded := labNativeRecoveryReadCalls()
		entered, returned := 0, 0
		for _, e := range events {
			if e.Core == core && e.Kind == "KERNEL_OS_WAIT_ENTER" {
				entered++
			}
			if e.Core == core && e.Kind == "KERNEL_OS_WAIT_RETURN" {
				returned++
			}
		}
		if !bounded || entered > 1 || returned != 0 || artifactContext(ctx) != nil {
			return errLabNativeRecovery
		}
		if entered == 1 {
			if !labRecoveryStartedOwnerCurrent(r.next, r.newIdentity) {
				return errLabNativeRecovery
			}
			// Identity/proc reads may overlap natural exit; retain all original
			// events and fail if its actual Wait already returned meanwhile.
			latest, bounded := labNativeRecoveryReadCalls()
			if !bounded {
				return errLabNativeRecovery
			}
			for _, e := range latest {
				if e.Core == core && e.Kind == "KERNEL_OS_WAIT_RETURN" {
					return errLabNativeRecovery
				}
			}
			if artifactContext(ctx) != nil {
				return errLabNativeRecovery
			}
			return nil
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-timer.C:
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return errLabNativeRecovery
		}
	}
}

func (r *labNativeRecoveryRunner) captureEvents(stage string) ([]labNativeRecoveryCall, error) {
	if r == nil || len(r.eventCheckpoints) >= 10 {
		return nil, errLabNativeRecovery
	}
	events, checkpoint, err := labNativeRecoveryEventSnapshot(stage)
	if err != nil {
		return nil, err
	}
	r.eventCheckpoints = append(r.eventCheckpoints, checkpoint)
	return events, nil
}

func (r *labNativeRecoveryRunner) cleanup(ctx context.Context) error {
	if r == nil || r.service == nil || artifactContext(ctx) != nil {
		return errLabNativeRecovery
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cleanupDone {
		return nil
	}
	// Retain the original new owned handle even alongside failed Start.
	if r.next != nil && !r.nextSettled {
		exit, err := r.next.stop(ctx)
		r.newExit = &exit
		if err != nil || !labQuiescenceExitDrained(exit) {
			return errLabNativeRecovery
		}
		r.nextSettled = true
	}
	if r.next != nil && !r.streamsSaved {
		stdout, stderr, err := labServiceKernelStreams(r.next)
		if err != nil || labNativeRecoveryWrite("new-kernel.stdout", stdout) != nil || labNativeRecoveryWrite("new-kernel.stderr", stderr) != nil {
			return errLabNativeRecovery
		}
		r.streamsSaved = true
	}
	if r.authority != nil && r.authority.close() != nil {
		return errLabNativeRecovery
	}
	c := r.service.core
	c.mu.Lock()
	c.busy = false // readiness remains false after takeover; no ordinary facade.
	c.mu.Unlock()
	if r.holdsClose {
		r.holdsClose = false
		c.closeMu.Unlock()
	}
	// Original old handle is independently reobserved by actual service.Close.
	// Its runtime now closes exactly the new recovery disk owner.
	if err := r.service.Close(ctx); err != nil {
		return err
	}
	r.cleanupDone = true
	return nil
}

func labNativeRecoveryReopen(legacy []byte, started lifecycleRecoveryExecution) (labNativeRecoveryCheckpoint, error) {
	var zero labNativeRecoveryCheckpoint
	d, fresh, err := openLabRuntimeDisk()
	if err != nil || d == nil || fresh {
		if d != nil {
			_ = d.close()
		}
		return zero, errLabNativeRecovery
	}
	s, err := openLifecycleRecoveryStore(d, time.Now().UTC())
	if err != nil {
		_ = d.close()
		return zero, err
	}
	defer s.close()
	x := s.core
	raw, exists, err := x.disk.readControl()
	if err != nil || !exists || !bytes.Equal(raw, x.raw) || x.verify() != nil {
		return zero, errLabNativeRecovery
	}
	w, err := decodeLifecycleV3Record(raw)
	if err != nil || w.core.Recovery == nil || w.core.Recovery.Phase != "RECOVERY_UNKNOWN" || w.core.Recovery.Completion != nil ||
		w.core.Recovery.Execution == nil || !reflect.DeepEqual(*w.core.Recovery.Execution, started) ||
		!bytes.Equal(w.core.SourceV2.ControlBytes, legacy) || x.live != nil || x.permit != nil || x.quiescenceSHA != "" {
		return zero, errLabNativeRecovery
	}
	// The durable record supplies no process-local owner, q or Start permit.
	if _, err := s.armRecoveryStart(nil, time.Now().UTC()); err == nil {
		return zero, errLabNativeRecovery
	}
	if err := labNativeRecoveryWrite("reopened-control.private.json", raw); err != nil {
		return zero, err
	}
	if err := s.close(); err != nil || !x.closed {
		return zero, errLabNativeRecovery
	}
	return labNativeRecoveryCheckpoint{"reopened", labConfigHash(raw), w.core.RecordSHA256, w.core.Revision, w.core.Recovery.Phase}, nil
}

// Marshal only detached observations, never this live runner or its handles.
func (*labNativeRecoveryRunner) MarshalJSON() ([]byte, error) {
	return nil, errLabNativeRecovery
}
