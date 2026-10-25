package mihomodeploy

import (
	"bytes"
	"encoding/json"
	"testing"
)

func labCurrentReadRuntimeModel(t *testing.T) (*labLifecycleRuntime, *labBootstrapModelDisk) {
	t.Helper()
	r, _, _, now := lifecycleV3Model(t)
	raw, err := encodeLifecycleV3Record(r)
	if err != nil {
		t.Fatal(err)
	}
	d := &labBootstrapModelDisk{lifecycleModelDisk: &lifecycleModelDisk{raw: bytes.Clone(raw), exists: true, state: lifecycleCommitted}, binding: r.core.Provisioning}
	s, err := openLifecycleRecoveryStore(d, now)
	if err != nil {
		t.Fatal(err)
	}
	return &labLifecycleRuntime{core: &labLifecycleRuntimeCore{disk: d, recovery: s}}, d
}

func TestLabCurrentEpochRuntimeSnapshotIsDetachedReadOnly(t *testing.T) {
	r, d := labCurrentReadRuntimeModel(t)
	before := bytes.Clone(d.raw)
	snapshot, present, err := r.recoverySnapshot()
	if err != nil || !present || snapshot.core == nil {
		t.Fatal("MODEL protected snapshot", err)
	}
	snapshot.core.SourceV2.ControlBytes[0] = '!'
	snapshot.core.Current.Head.PID++
	second, present, err := r.recoverySnapshot()
	if err != nil || !present || second.core.Current.Head.PID == snapshot.core.Current.Head.PID ||
		!bytes.Equal(d.raw, before) || d.writes != 0 {
		t.Fatal("MODEL diagnostic read modified source or published state")
	}
	x := r.core.recovery.core
	if r.core.store != nil || r.core.current != nil || x.live != nil || x.currentLive != nil || x.retainedStarted != nil || x.permit != nil {
		t.Fatal("MODEL snapshot reconstructed process-local authority")
	}
	if err := r.close(); err != nil || !d.closed {
		t.Fatal("MODEL lost sole disk close owner", err)
	}
}

func TestLabCurrentEpochRuntimeRejectsPoisonedOrForeignDiskWithoutLegacyFallback(t *testing.T) {
	for _, kind := range []string{"poisoned", "foreign-disk", "mixed-owner", "changed-bytes"} {
		t.Run(kind, func(t *testing.T) {
			r, d := labCurrentReadRuntimeModel(t)
			switch kind {
			case "poisoned":
				r.core.recovery.core.poisoned = true
			case "foreign-disk":
				r.core.disk = &labBootstrapModelDisk{lifecycleModelDisk: &lifecycleModelDisk{raw: bytes.Clone(d.raw)}, binding: d.binding}
			case "mixed-owner":
				r.core.store = &lifecycleStore{}
			case "changed-bytes":
				d.raw = append(d.raw, ' ')
			}
			if _, present, err := r.recoverySnapshot(); err == nil || !present || d.writes != 0 {
				t.Fatal("MODEL failed V3 custody fell back to ordinary writer")
			}
		})
	}
}

func TestLabCurrentEpochRuntimeRejectsUnissuedHandoffAndPreservesCloseOwner(t *testing.T) {
	r, d := labCurrentReadRuntimeModel(t)
	before, _ := json.Marshal(r.core.recovery.core.record.core)
	if _, _, err := r.adoptCurrentEpoch(nil, r.core.recovery); err == nil {
		t.Fatal("MODEL nil handoff adopted writer")
	}
	if _, _, err := r.adoptCurrentEpoch(&lifecycleRecoveryCurrentHandoff{}, r.core.recovery); err == nil {
		t.Fatal("MODEL DTO handoff adopted writer")
	}
	after, _ := json.Marshal(r.core.recovery.core.record.core)
	if !bytes.Equal(before, after) || r.core.current != nil || d.writes != 0 || d.closed {
		t.Fatal("MODEL rejected handoff changed owner")
	}
	if err := r.close(); err != nil || !d.closed {
		t.Fatal("MODEL rejected handoff lost real disk owner", err)
	}
}
