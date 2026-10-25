package mihomodeploy

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

// MODEL ONLY: these tests exercise resource and representation guards. They do
// not prove an owned kernel, HTTP flow, filesystem durability or production.
func TestLifecycleV3DecodeScopeMemoUsesExactCanonicalBytesAndDetachedValues(t *testing.T) {
	r, _, _, _ := lifecycleV3Model(t)
	raw, err := encodeLifecycleV3Record(r)
	if err != nil {
		t.Fatal("MODEL canonical source", err)
	}
	scope := newLifecycleV3DecodeScope()
	first, err := decodeLifecycleV3RecordScoped(raw, scope)
	if err != nil || scope.roots != 1 || scope.validated != 1 || scope.memoHits != 0 {
		t.Fatal("MODEL first strict decode did not populate one exact root", err, scope.roots, scope.validated, scope.memoHits)
	}
	key := lifecycleV3DecodeMemoKey{bytes: len(raw), sha256: sha256.Sum256(raw)}
	seal := scope.memo[key]
	if seal == nil || seal.identity != seal || seal.scope != scope || seal.key != key || seal.recordSHA256 != r.core.RecordSHA256 {
		t.Fatal("MODEL full validation did not issue a private byte-derived seal")
	}
	first.core.Revision++
	second, err := decodeLifecycleV3RecordScoped(raw, scope)
	if err != nil || scope.roots != 1 || scope.validated != 1 || scope.memoHits != 1 || second.core.Revision != r.core.Revision {
		t.Fatal("MODEL memo aliased caller state or revalidated the same bytes", err, scope.roots, scope.validated, scope.memoHits)
	}
	changed := append(bytes.Clone(raw), ' ')
	if _, err := decodeLifecycleV3RecordScoped(changed, scope); err == nil || scope.memoHits != 1 {
		t.Fatal("MODEL noncanonical bytes reused an exact-byte memo entry")
	}
}

func TestLifecycleV3DecodeScopeCheckpointRootIsStrictlyValidatedOnce(t *testing.T) {
	r, _, _, _ := lifecycleV3Model(t)
	checkpoint, err := lifecycleRecoveryCheckpoint(r.core, lifecycleRecoveryCheckpointNone)
	if err != nil {
		t.Fatal("MODEL checkpoint", err)
	}
	scope := newLifecycleV3DecodeScope()
	raw, err := lifecycleRecoveryCheckpointPreimageScoped(r.core, checkpoint, nil, scope)
	if err != nil || scope.roots != 1 || scope.validated != 1 {
		t.Fatal("MODEL checkpoint root was not fully strict-decoded once", err, scope.roots, scope.validated)
	}
	again, err := lifecycleRecoveryCheckpointPreimageScoped(r.core, checkpoint, nil, scope)
	if err != nil || !bytes.Equal(raw, again) || scope.roots != 1 || scope.validated != 1 || scope.memoHits != 1 {
		t.Fatal("MODEL repeated checkpoint root missed exact canonical memo", err, scope.roots, scope.validated, scope.memoHits)
	}
	bad := checkpoint
	replacement := byte('0')
	if bad.CurrentLedgerSHA256[0] == replacement {
		replacement = '1'
	}
	bad.CurrentLedgerSHA256 = string(replacement) + bad.CurrentLedgerSHA256[1:]
	if _, err := lifecycleRecoveryCheckpointPreimageScoped(r.core, bad, nil, scope); err == nil || scope.memoHits != 1 {
		t.Fatal("MODEL changed checkpoint reused a validated root")
	}
}

func TestLifecycleV3DecodeScopesNeverShareValidationAcrossOperations(t *testing.T) {
	r, _, _, _ := lifecycleV3Model(t)
	raw, err := encodeLifecycleV3Record(r)
	if err != nil {
		t.Fatal("MODEL canonical source", err)
	}
	first := newLifecycleV3DecodeScope()
	second := newLifecycleV3DecodeScope()
	if _, err := decodeLifecycleV3RecordScoped(raw, first); err != nil {
		t.Fatal("MODEL first operation", err)
	}
	if _, err := decodeLifecycleV3RecordScoped(raw, second); err != nil {
		t.Fatal("MODEL second operation", err)
	}
	if first.validated != 1 || second.validated != 1 || first.memoHits != 0 || second.memoHits != 0 || first == second {
		t.Fatal("MODEL validation crossed operation scope")
	}
}

func TestLifecycleV3DecodeScopeDeepChainBudgetsFailClosed(t *testing.T) {
	scope := newLifecycleV3DecodeScope()
	if scope.charge(maxLifecycleV3DecodeWork) != nil || scope.work != maxLifecycleV3DecodeWork {
		t.Fatal("MODEL exact work budget rejected")
	}
	if scope.charge(1) == nil || scope.work != maxLifecycleV3DecodeWork {
		t.Fatal("MODEL work overflow did not fail closed")
	}
	r, _, _, _ := lifecycleV3Model(t)
	raw, err := encodeLifecycleV3Record(r)
	if err != nil {
		t.Fatal("MODEL canonical source", err)
	}
	rootScope := newLifecycleV3DecodeScope()
	rootScope.roots = maxLifecycleV3DecodeRoots
	if _, err := decodeLifecycleV3RecordScoped(raw, rootScope); err == nil {
		t.Fatal("MODEL root budget overflow did not fail closed")
	}
	depthScope := newLifecycleV3DecodeScope()
	depthScope.depth = maxLifecycleV3DecodeDepth
	if _, err := decodeLifecycleV3RecordScoped(raw, depthScope); err == nil {
		t.Fatal("MODEL depth budget overflow did not fail closed")
	}
}
