package mihomo

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// These tests reuse source-derived MODEL HTTP responses. They are not real
// kernel acceptance, private-payload proof, authorization or recovery facts.
func labTargetTestCloneSamples(t *testing.T, in LabSamples) LabSamples {
	t.Helper()
	if in.core == nil {
		t.Fatal("MODEL sample clone requires a real test-reader result")
	}
	copyCore := *in.core
	for i := range copyCore.samples {
		raw := labTestJSON(t, in.core.samples[i].projection)
		var projection labProjection
		if json.Unmarshal(raw, &projection) != nil {
			t.Fatal("MODEL projection clone rejected")
		}
		copyCore.samples[i].projection = projection
	}
	return LabSamples{core: &copyCore}
}

func labTargetTestBounded(t *testing.T, r LabTargetReadbackReport) {
	t.Helper()
	if r.Schema != "chengwang.mihomo-selected-target-readback/v1" || r.SampleCount != 2 || r.RequestsObserved != 8 || r.TargetProjectionSHA256 == "" || r.DataplaneProven || r.FullPayloadProven || r.AuthorizationProven || r.Production {
		t.Fatal("MODEL selected target gained unsupported claims")
	}
}

func TestLabTargetReadbackMatchesEitherSelectedEpochWithoutOldNewClaim(t *testing.T) {
	for _, candidate := range []bool{false, true} {
		name := "previous_selected"
		if candidate {
			name = "candidate_selected"
		}
		t.Run(name, func(t *testing.T) {
			bodies := labTestBodies(t, candidate)
			samples := labTestRead(t, bodies, bodies)
			target := labTestExpected(t, candidate)
			old, err := CompareLabReadback(samples, target, target)
			if err != nil || old.Conclusion != LabProjectionAmbiguous {
				t.Fatal("MODEL original equal-expectation API changed")
			}
			selected, err := CompareLabTargetReadback(samples, target)
			if err != nil || selected.Conclusion != LabTargetProjectionMatched || selected.ObservedProjectionSHA256 == nil || *selected.ObservedProjectionSHA256 != target.core.digest || selected.TargetProjectionSHA256 != target.core.digest {
				t.Fatal("MODEL explicitly selected target projection did not match")
			}
			labTargetTestBounded(t, selected)
			if string(selected.Conclusion) == string(LabStableNewProjection) || string(selected.Conclusion) == string(LabStableOldProjection) {
				t.Fatal("MODEL target match was labeled as old/new epoch identification")
			}
			opposite := labTestExpected(t, !candidate)
			drift, err := CompareLabTargetReadback(samples, opposite)
			if err != nil || drift.Conclusion != LabTargetProjectionDrift || drift.ObservedProjectionSHA256 == nil {
				t.Fatal("MODEL target identity was ignored")
			}
			labTargetTestBounded(t, drift)
		})
	}
}

func TestLabTargetReadbackPreservesProjectionAndWitnessInstability(t *testing.T) {
	target := labTestExpected(t, false)
	first, second := labTestBodies(t, false), labTestBodies(t, true)
	changedWitness := labTestBodies(t, false)
	changedWitness["/proxies"] = labTestMutate(t, changedWitness["/proxies"], func(m map[string]any) {
		m["proxies"].(map[string]any)["http-a"].(map[string]any)["id"] = "22222222-2222-4222-8222-222222222222"
	})
	for name, body := range map[string]map[string][]byte{"projection": second, "runtime_witness": changedWitness} {
		t.Run(name, func(t *testing.T) {
			samples := labTestRead(t, first, body)
			legacy, err := CompareLabReadback(samples, target, target)
			if err != nil || legacy.Conclusion != LabProjectionUnstable {
				t.Fatal("MODEL original unstable positive control failed")
			}
			r, err := CompareLabTargetReadback(samples, target)
			if err != nil || r.Conclusion != LabTargetProjectionUnstable || r.ObservedProjectionSHA256 != nil {
				t.Fatal("MODEL unstable capture became a target match")
			}
			labTargetTestBounded(t, r)
		})
	}
}

func TestLabTargetReadbackRetainsOriginalInputDigestAndTimeGuards(t *testing.T) {
	bodies := labTestBodies(t, false)
	seed := labTestRead(t, bodies, bodies)
	target := labTestExpected(t, false)
	if r, err := CompareLabTargetReadback(seed, target); err != nil || r.Conclusion != LabTargetProjectionMatched {
		t.Fatal("MODEL valid seed rejected before negative cases")
	}
	for name, edit := range map[string]func(*labSamplesCore){
		"seven_requests": func(s *labSamplesCore) { s.requests = 7 },
		"nine_requests": func(s *labSamplesCore) { s.requests = 9 },
		"digest_changed": func(s *labSamplesCore) { s.samples[1].digest = strings.Repeat("0", 64) },
		"projection_changed_without_digest": func(s *labSamplesCore) { s.samples[1].projection.General = json.RawMessage(`{}`) },
		"missing_witness": func(s *labSamplesCore) { s.samples[0].witness = "" },
		"zero_started": func(s *labSamplesCore) { s.samples[0].started = time.Time{} },
		"zero_completed": func(s *labSamplesCore) { s.samples[1].completed = time.Time{} },
	} {
		t.Run(name, func(t *testing.T) {
			bad := labTargetTestCloneSamples(t, seed)
			edit(bad.core)
			if r, err := CompareLabTargetReadback(bad, target); !errors.Is(err, ErrLabReadbackInput) || !reflect.DeepEqual(r, LabTargetReadbackReport{}) {
				t.Fatal("MODEL invalid sample obtained a selected-target report")
			}
		})
	}
	for name, edit := range map[string]func(*labSamplesCore){
		"first_completed_before_start": func(s *labSamplesCore) { s.samples[0].completed = s.samples[0].started.Add(-time.Nanosecond) },
		"second_started_before_first_completed": func(s *labSamplesCore) { s.samples[1].started = s.samples[0].completed.Add(-time.Nanosecond) },
		"second_completed_before_start": func(s *labSamplesCore) { s.samples[1].completed = s.samples[1].started.Add(-time.Nanosecond) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := labTargetTestCloneSamples(t, seed)
			edit(bad.core)
			r, err := CompareLabTargetReadback(bad, target)
			if err != nil || r.Conclusion != LabTargetProjectionUnstable || r.ObservedProjectionSHA256 != nil {
				t.Fatal("MODEL invalid sample order became a selected-target match")
			}
			labTargetTestBounded(t, r)
		})
	}
	for name, edit := range map[string]func(*labExpectedCore){
		"not_constructed": func(e *labExpectedCore) { e.constructed = false },
		"expected_digest_changed": func(e *labExpectedCore) { e.digest = strings.Repeat("0", 64) },
		"expected_projection_changed": func(e *labExpectedCore) { e.projection.General = json.RawMessage(`{}`) },
	} {
		t.Run(name, func(t *testing.T) {
			copyCore := *target.core
			bad := LabExpectation{core: &copyCore}
			edit(bad.core)
			if r, err := CompareLabTargetReadback(seed, bad); !errors.Is(err, ErrLabReadbackInput) || !reflect.DeepEqual(r, LabTargetReadbackReport{}) {
				t.Fatal("MODEL changed expectation obtained a selected-target report")
			}
		})
	}
	for _, input := range []struct {
		samples LabSamples
		target  LabExpectation
	}{{LabSamples{}, target}, {seed, LabExpectation{}}, {LabSamples{}, LabExpectation{}}} {
		if r, err := CompareLabTargetReadback(input.samples, input.target); !errors.Is(err, ErrLabReadbackInput) || !reflect.DeepEqual(r, LabTargetReadbackReport{}) {
			t.Fatal("MODEL missing opaque input obtained a selected-target report")
		}
	}
}

func TestLabTargetReadbackClosedMappingAndReportOwnership(t *testing.T) {
	bodies := labTestBodies(t, false)
	samples := labTestRead(t, bodies, bodies)
	target := labTestExpected(t, false)
	comparison, err := CompareLabReadback(samples, target, target)
	if err != nil || comparison.Conclusion != LabProjectionAmbiguous {
		t.Fatal("MODEL original comparison control failed")
	}
	mapped, err := labTargetReadbackFromComparison(comparison)
	if err != nil || mapped.Conclusion != LabTargetProjectionMatched || mapped.ObservedProjectionSHA256 == nil {
		t.Fatal("MODEL closed mapping valid control failed")
	}
	// Mutate the very mapper result derived from this comparison. A fresh
	// public comparison would allocate another pointer and hide this alias.
	originalObserved := *comparison.ObservedProjectionSHA256
	*mapped.ObservedProjectionSHA256 = "CALLER_CHANGED_PRIVATE_MAPPING"
	if *comparison.ObservedProjectionSHA256 != originalObserved {
		t.Fatal("MODEL private mapping report aliases its input comparison")
	}
	for _, conclusion := range []LabReadbackConclusion{LabStableNewProjection, LabStableOldProjection, "FUTURE_CONCLUSION", ""} {
		bad := comparison
		bad.Conclusion = conclusion
		if r, err := labTargetReadbackFromComparison(bad); !errors.Is(err, ErrLabReadbackInput) || !reflect.DeepEqual(r, LabTargetReadbackReport{}) {
			t.Fatal("MODEL unknown/old-new conclusion bypassed selected-target semantics")
		}
	}
	for name, edit := range map[string]func(*LabReadbackReport){
		"count": func(r *LabReadbackReport) { r.SampleCount = 1 },
		"requests": func(r *LabReadbackReport) { r.RequestsObserved = 7 },
		"different_targets": func(r *LabReadbackReport) { r.PreviousProjectionSHA256 = "DIFFERENT" },
		"missing_observed": func(r *LabReadbackReport) { r.ObservedProjectionSHA256 = nil },
		"wrong_observed": func(r *LabReadbackReport) { v := "DIFFERENT"; r.ObservedProjectionSHA256 = &v },
		"dataplane": func(r *LabReadbackReport) { r.DataplaneProven = true },
		"full_payload": func(r *LabReadbackReport) { r.FullPayloadProven = true },
		"authorization": func(r *LabReadbackReport) { r.AuthorizationProven = true },
		"production": func(r *LabReadbackReport) { r.Production = true },
	} {
		t.Run(name, func(t *testing.T) {
			bad := comparison
			edit(&bad)
			if r, err := labTargetReadbackFromComparison(bad); !errors.Is(err, ErrLabReadbackInput) || !reflect.DeepEqual(r, LabTargetReadbackReport{}) {
				t.Fatal("MODEL inconsistent comparison report obtained a target match")
			}
		})
	}
	r, err := CompareLabTargetReadback(samples, target)
	if err != nil {
		t.Fatal("MODEL selected target report rejected")
	}
	before := labTargetTestCloneSamples(t, samples)
	expectedDigest := target.core.digest
	*r.ObservedProjectionSHA256 = "CALLER_CHANGED"
	r.TargetProjectionSHA256 = "CALLER_CHANGED"
	r.DataplaneProven, r.FullPayloadProven, r.AuthorizationProven, r.Production = true, true, true, true
	if *comparison.ObservedProjectionSHA256 != expectedDigest || !reflect.DeepEqual(samples.core, before.core) {
		t.Fatal("MODEL report alias changed original comparison or samples")
	}
	after, err := CompareLabTargetReadback(samples, target)
	if err != nil || after.Conclusion != LabTargetProjectionMatched || after.ObservedProjectionSHA256 == nil || *after.ObservedProjectionSHA256 != expectedDigest || target.core.digest != expectedDigest {
		t.Fatal("MODEL caller report mutation changed retained inputs")
	}
	labTargetTestBounded(t, after)
	raw := labTestJSON(t, after)
	var fields map[string]any
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 10 || bytes.Contains(raw, []byte(string(LabStableNewProjection))) || bytes.Contains(raw, []byte(labTestSecret)) {
		t.Fatal("MODEL selected-target report expanded or leaked private data")
	}
}
