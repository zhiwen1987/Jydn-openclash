package mihomodeploy

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

// Closed shape/copy/denial tests only. No listener, HTTP, native capability,
// registered route receipt, service factory bypass or global issuer is used.
func TestLabRecoveryMarkerClosedDiagnosticNamesAndDetachedProjection(t *testing.T) {
	for _, cancelOwner := range []bool{false, true} {
		canceled, finish := context.WithCancel(context.Background())
		finish()
		caller, owner := context.Background(), context.Background()
		if cancelOwner {
			owner = canceled
		} else {
			caller = canceled
		}
		phase, cancel, err := labRecoveryPhaseContext(caller, owner, time.Now().UTC().Add(time.Minute))
		if err == nil || phase != nil || cancel != nil {
			t.Fatal("already canceled caller or service acquired a phase")
		}
	}
	for _, cancelOwner := range []bool{false, true} {
		caller, callerCancel := context.WithCancel(context.Background())
		owner, ownerCancel := context.WithCancel(context.Background())
		deadline := time.Now().UTC().Add(time.Minute)
		phase, cancel, err := labRecoveryPhaseContext(caller, owner, deadline)
		if err != nil {
			t.Fatal("ordinary caller/owner contexts could not establish the phase")
		}
		actualDeadline, ok := phase.Deadline()
		if !ok || !actualDeadline.Equal(deadline) {
			t.Fatal("phase extended or lost its source deadline")
		}
		if cancelOwner {
			ownerCancel()
		} else {
			callerCancel()
		}
		select {
		case <-phase.Done():
		case <-time.After(time.Second):
			t.Fatal("phase outlived caller or original service cancellation")
		}
		cancel()
		ownerCancel()
		callerCancel()
	}
	for _, ownerEarlier := range []bool{false, true} {
		bound := time.Now().UTC().Add(time.Minute)
		bounded, boundedCancel := context.WithDeadline(context.Background(), bound)
		caller, owner := context.Background(), context.Background()
		if ownerEarlier {
			owner = bounded
		} else {
			caller = bounded
		}
		phase, cancel, err := labRecoveryPhaseContext(caller, owner, bound.Add(time.Minute))
		actualDeadline, ok := phase.Deadline()
		if err != nil || !ok || !actualDeadline.Equal(bound) {
			t.Fatal("phase extended caller or original service deadline")
		}
		cancel()
		boundedCancel()
	}
	if !labDiagnosticName("recovery-s2/local-marker.json") {
		t.Fatal("fixed local original unavailable")
	}
	for _, path := range []string{"bootstrap/local-marker.json", "op-01/create/local-marker.json", "recovery-s2/local-marker-2.json", "recovery-s2/../local-marker.json", "recovery-s2/sub/local-marker.json"} {
		if labDiagnosticName(path) {
			t.Fatal("marker capture widened another phase or path")
		}
	}
	v := labRecoveryLocalMarkerValue{Route: labLocalRoute{Phase: labRecoveryLocalPhase,
		ClientResponse: &labLocalBody{SHA256: "MODEL", Bytes: 1, Complete: true},
		ProxyResponse: &labLocalBody{SHA256: "MODEL", Bytes: 1, Complete: true},
		OriginResponse: &labLocalBody{SHA256: "MODEL", Bytes: 1, Complete: true},
		CountersBefore: []labLocalCounter{{Role: "A"}, {Role: "B"}, {Role: "origin"}},
		CountersAfter: []labLocalCounter{{Role: "A"}, {Role: "B"}, {Role: "origin"}}}}
	copy := labRecoveryCloneMarker(v)
	copy.Route.ClientResponse.Bytes++
	copy.Route.ProxyResponse.Bytes++
	copy.Route.OriginResponse.Bytes++
	copy.Route.CountersBefore[0].Rejected++
	copy.Route.CountersAfter[2].OriginRequests++
	if v.Route.ClientResponse.Bytes != 1 || v.Route.ProxyResponse.Bytes != 1 || v.Route.OriginResponse.Bytes != 1 ||
		v.Route.CountersBefore[0].Rejected != 0 || v.Route.CountersAfter[2].OriginRequests != 0 {
		t.Fatal("public projection copy aliases retained observations")
	}
	if labRecoveryMarkerValueValid(copy) {
		t.Fatal("MODEL projection was promoted to actual marker success")
	}
}

func TestLabRecoveryMarkerUnissuedServiceAndReceiptCannotAuthorize(t *testing.T) {
	var seal labServiceFixtureCustody
	if seal.current(nil, nil) || seal.currentLocked(nil, nil) {
		t.Fatal("empty metadata claimed source fixture custody")
	}
	if json.Unmarshal([]byte(`{"fixture":{},"service":{}}`), &seal) == nil {
		t.Fatal("serialized service fields constructed source ownership")
	}
	if _, err := json.Marshal(seal); err == nil {
		t.Fatal("fixture custody was exported as an authority DTO")
	}
	f := &labLocalFixture{}
	receipt := &labRecoveryMarkerReceipt{owner: f, value: labRecoveryLocalMarkerValue{Route: labLocalRoute{Matched: true}}}
	if value, err := f.consumeRecoveryReceipt(context.Background(), receipt, receipt.value.Route); err == nil || !reflect.DeepEqual(value, labRecoveryLocalMarkerValue{}) {
		t.Fatal("unregistered Matched DTO became a source receipt")
	}
	copy := *receipt
	if _, err := f.consumeRecoveryReceipt(context.Background(), &copy, receipt.value.Route); err == nil {
		t.Fatal("copied unissued receipt became a capability")
	}
	if json.Unmarshal([]byte(`{"owner":{},"value":{"route":{"matched":true}}}`), receipt) == nil {
		t.Fatal("JSON constructed route receipt membership")
	}
	if _, err := json.Marshal(receipt); err == nil {
		t.Fatal("route receipt serialized as authority")
	}
}
