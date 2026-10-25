package mihomodeploy

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestLifecycleRecoveryVerificationVersionedCodecPreservesLegacyExecutionBytes(t *testing.T) {
	e := lifecycleRecoveryExecution{Schema: lifecycleRecoveryExecutionSchema, ArmedFailedQuiescence: []labQuiescenceObservation{}}
	// Exact old nine-field encoder, independently written rather than removing
	// a new JSON key after serialization. No new v2 meaning is assigned to v1.
	old := struct {
		Schema string `json:"schema"`
		Started labRecoveryStartedFact `json:"started"`
		ArmedOwner lifecycleOwner `json:"armedOwner"`
		ArmedLastTrustedAt time.Time `json:"armedLastTrustedAt"`
		ArmedLastRecoveryFence uint64 `json:"armedLastRecoveryFence"`
		ArmedRecoveryUpdatedAt time.Time `json:"armedRecoveryUpdatedAt"`
		ArmedFailedQuiescence []labQuiescenceObservation `json:"armedFailedQuiescence"`
		StartedCommitRevision uint64 `json:"startedCommitRevision"`
		RecordedAt time.Time `json:"recordedAt"`
	}{e.Schema, e.Started, e.ArmedOwner, e.ArmedLastTrustedAt, e.ArmedLastRecoveryFence, e.ArmedRecoveryUpdatedAt, e.ArmedFailedQuiescence, e.StartedCommitRevision, e.RecordedAt}
	want, err := json.Marshal(old)
	if err != nil {
		t.Fatal("MODEL old execution encoding unavailable")
	}
	actual, err := json.Marshal(e)
	if err != nil || !bytes.Equal(want, actual) || bytes.Contains(actual, []byte(`"verification"`)) {
		t.Fatal("v1 canonical bytes acquired a v2 field or changed order")
	}
	if !lifecycleRecoveryVerificationFieldsValid(lifecycleRecoveryTxn{Execution: &e}, time.Time{}, 0) {
		t.Fatal("nil optional verification changed the v1-only branch")
	}
	e.Schema = lifecycleRecoveryVerifiedExecutionSchema
	if lifecycleRecoveryVerificationFieldsValid(lifecycleRecoveryTxn{Execution: &e}, time.Time{}, 0) {
		t.Fatal("v2 was accepted without a typed verification fact")
	}
	e.Schema = lifecycleRecoveryExecutionSchema
	e.Verification = &lifecycleRecoveryVerification{}
	if lifecycleRecoveryVerificationFieldsValid(lifecycleRecoveryTxn{Execution: &e}, time.Time{}, 0) {
		t.Fatal("v1 accepted the new verification contract")
	}
}

func TestLifecycleRecoveryVerificationTypedFactRejectsUnissuedRecordCapability(t *testing.T) {
	v := labRecoveryObservedValue{}
	fact := lifecycleRecoveryObservedFromValue(v)
	if fact.SampleTimes == nil || len(fact.SampleTimes) != 2 || fact.BodySHA256s == nil || len(fact.BodySHA256s) != 8 {
		t.Fatal("memory arrays were not converted to exact typed nonnil bounds")
	}
	fact.BodySHA256s[0] = "MODEL"
	if v.BodySHA256s[0] != "" || lifecycleRecoveryObservedValid(fact, lifecycleRecoveryTxn{}, lifecycleOwner{}) {
		t.Fatal("detached MODEL metadata became a genuine verification")
	}
	collector := &labRecoveryCollector{}
	if _, cap, err := collector.consumeForRecord(context.Background(), nil, &labRecoveryObservedEvidence{}); err == nil || cap != nil {
		t.Fatal("unissued observation minted a record capability")
	}
	cap := &labRecoveryVerificationRecordCap{core: &labRecoveryVerificationRecordCore{value: fact}}
	store := &lifecycleRecoveryStore{}
	if store.recordRecoveryVerification(nil, cap, time.Now().UTC()) == nil {
		t.Fatal("unregistered typed fact was recorded")
	}
	copy := *cap.core
	if store.recordRecoveryVerification(nil, &labRecoveryVerificationRecordCap{core: &copy}, time.Now().UTC()) == nil {
		t.Fatal("copied unissued record metadata bypassed original membership")
	}
	if _, err := json.Marshal(cap); err == nil {
		t.Fatal("record capability became an authority DTO")
	}
	if json.Unmarshal([]byte(`{"core":{"value":{}}}`), cap) == nil || !reflect.DeepEqual(*cap, labRecoveryVerificationRecordCap{}) {
		t.Fatal("serialized data constructed record authority")
	}
}
