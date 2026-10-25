//go:build linux

package mihomodeploy

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestLifecycleRecoveryCompletionCheckpointReconstructsExactVerifiedRoot(t *testing.T) {
	_, _, _, _, verified := lifecycleVerifiedBoundsModel(t)
	source, err := json.Marshal(verified.core)
	if err != nil {
		t.Fatal("MODEL verified source encoding")
	}
	checkpoint, err := lifecycleRecoveryCheckpoint(verified.core, lifecycleRecoveryCheckpointVerified)
	if err != nil {
		t.Fatal("MODEL verified checkpoint")
	}
	var completed lifecycleV3Wire
	if json.Unmarshal(source, &completed) != nil {
		t.Fatal("MODEL completion copy")
	}
	committedAt := completed.LastTrustedAt.Add(time.Nanosecond)
	deadline := committedAt.Add(time.Second)
	completed.Revision++
	completed.LastTrustedAt = committedAt
	completed.Recovery.Phase = "COMPLETED"
	completed.Recovery.UpdatedAt = committedAt
	completed.Recovery.Execution.Schema = lifecycleRecoveryCompletedExecutionSchema
	completed.Recovery.Execution.CompletionSource = &lifecycleRecoveryCompletionSource{Schema: lifecycleRecoveryCompletionSourceSchema, Root: checkpoint, CommitDeadline: deadline}
	completed.Recovery.Completion = &lifecycleRecoveryCompletion{CommitRevision: completed.Revision, CommittedAt: committedAt}
	preimage, err := lifecycleRecoveryCompletionPreimage(&completed, *completed.Recovery)
	if err != nil || !bytes.Equal(preimage, source) {
		t.Fatal("typed checkpoint did not reconstruct exact verified root")
	}
	completed.Recovery.Execution.CompletionSource.Root.CurrentLedgerSHA256 = labConfigHash([]byte("MODEL forged ledger"))
	if _, err := lifecycleRecoveryCompletionPreimage(&completed, *completed.Recovery); err == nil {
		t.Fatal("changed checkpoint ledger digest reconstructed authority")
	}
}

func TestLifecycleRecoveryCompletionProspectiveMetadataUsesStrictS2Preimage(t *testing.T) {
	_, _, _, _, verified := lifecycleVerifiedBoundsModel(t)
	source, err := json.Marshal(verified.core)
	if err != nil {
		t.Fatal("MODEL verified source encoding")
	}
	checkpoint, err := lifecycleRecoveryCheckpoint(verified.core, lifecycleRecoveryCheckpointVerified)
	if err != nil {
		t.Fatal("MODEL verified checkpoint")
	}
	var draft lifecycleV3Wire
	if json.Unmarshal(source, &draft) != nil {
		t.Fatal("MODEL completion draft copy")
	}
	oldRevision, oldTrustedAt := draft.Revision, draft.LastTrustedAt
	committedAt := oldTrustedAt.Add(time.Nanosecond)
	draft.Recovery.Phase = "COMPLETED"
	draft.Recovery.UpdatedAt = committedAt
	draft.Recovery.Execution.Schema = lifecycleRecoveryCompletedExecutionSchema
	draft.Recovery.Execution.CompletionSource = &lifecycleRecoveryCompletionSource{
		Schema: lifecycleRecoveryCompletionSourceSchema, Root: checkpoint, CommitDeadline: committedAt.Add(time.Second),
	}
	draft.Recovery.Completion = &lifecycleRecoveryCompletion{CommitRevision: oldRevision + 1, CommittedAt: committedAt}
	if _, err := lifecycleRecoveryCompletionPreimage(&draft, *draft.Recovery); err == nil {
		t.Fatal("persisted validator accepted old draft revision/time")
	}
	final, err := lifecycleRecoveryCompletionProspectiveRoot(&draft, *draft.Recovery)
	if err != nil || final == &draft || final.Revision != oldRevision+1 || !final.LastTrustedAt.Equal(committedAt) {
		t.Fatal("prospective final metadata rejected")
	}
	if draft.Revision != oldRevision || !draft.LastTrustedAt.Equal(oldTrustedAt) {
		t.Fatal("prospective metadata advanced the draft root")
	}
	preimage, err := lifecycleRecoveryCompletionPreimage(final, *draft.Recovery)
	if err != nil || !bytes.Equal(preimage, source) {
		t.Fatal("prospective final metadata did not recover exact strict S2")
	}
}

func TestLifecycleRecoveryCompletionCustodyRejectsCopiesForeignResetAndReopen(t *testing.T) {
	disk := &lifecycleModelDisk{}
	owner := &lifecycleRecoveryOwnerCore{}
	started := &labRecoveryStartedCustody{}
	observation := lifecycleRecoveryObservedFact{}
	record := &labRecoveryVerificationRecordCore{custody: started, value: observation}
	x := &lifecycleRecoveryStoreCore{disk: disk, live: owner, raw: []byte("MODEL verified canonical")}
	x.record = lifecycleV3Record{core: &lifecycleV3Wire{Recovery: &lifecycleRecoveryTxn{Execution: &lifecycleRecoveryExecution{
		Schema: lifecycleRecoveryVerifiedExecutionSchema, Verification: &lifecycleRecoveryVerification{Observation: observation},
	}}}}
	custody := &labRecoveryVerifiedCustody{store: x, disk: disk, owner: owner, started: started, record: record, canonical: string(x.raw)}
	custody.binding = func(candidate *labRecoveryVerifiedCustody, current *lifecycleRecoveryStoreCore) bool {
		return candidate == custody && current == x && candidate.store == x && candidate.disk == disk && candidate.owner == owner &&
			candidate.started == started && candidate.record == record && candidate.canonical == string(x.raw)
	}
	x.retainedVerified = custody
	if !custody.matches(x) {
		t.Fatal("MODEL exact retained S2 custody rejected")
	}
	copy := *custody
	if copy.matches(x) {
		t.Fatal("copied S2 custody acquired completion authority")
	}
	foreign := *x
	if custody.matches(&foreign) {
		t.Fatal("foreign store acquired completion authority")
	}
	x.retainedVerified = nil
	if custody.matches(x) {
		t.Fatal("reset store retained completion authority")
	}
	reopened := &lifecycleRecoveryStoreCore{disk: disk, live: owner, raw: bytes.Clone(x.raw), record: x.record}
	if custody.matches(reopened) {
		t.Fatal("reopened store reconstructed process-local completion authority")
	}
}

func TestLifecycleRecoveryCompletionCapabilitiesArePrivateAndOneStoreBound(t *testing.T) {
	cap := &labRecoveryCompletionCap{core: &labRecoveryCompletionCapCore{}}
	if _, err := json.Marshal(cap); err == nil {
		t.Fatal("completion capability became JSON")
	}
	if json.Unmarshal([]byte(`{"core":{}}`), cap) == nil || !reflect.DeepEqual(*cap, labRecoveryCompletionCap{}) {
		t.Fatal("completion capability restored from JSON")
	}
	handoff := &lifecycleRecoveryCurrentHandoff{core: &lifecycleRecoveryCurrentHandoffCore{}}
	if _, err := json.Marshal(handoff); err == nil {
		t.Fatal("current handoff became JSON")
	}
	if json.Unmarshal([]byte(`{"core":{}}`), handoff) == nil || !reflect.DeepEqual(*handoff, lifecycleRecoveryCurrentHandoff{}) {
		t.Fatal("current handoff restored from JSON")
	}
	if _, err := handoff.consumeCurrent(&lifecycleRecoveryStoreCore{}); err == nil {
		t.Fatal("unissued current handoff minted an owner")
	}
}

func TestLifecycleCloneSchemaDigestForRecoveryCompletion(t *testing.T) {
	digest, walked := lifecycleCloneTypeShape(reflect.TypeOf(lifecycleV3Wire{}))
	if !walked || !lifecycleNonzeroHash(digest) {
		t.Fatal("completion record graph is not closed")
	}
	t.Logf("lifecycleCloneSchemaSHA256=%s", digest)
}
