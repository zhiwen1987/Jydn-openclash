package mihomo

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

// These tests use the actual opaque readStable creation path against existing
// source-derived MODEL HTTP fixtures. They are not pinned-kernel acceptance.
func TestLabSampleTimesUsesOpaqueCaptureAndReturnsDetachedValues(t *testing.T) {
	bodies := labTestBodies(t, false)
	samples := labTestRead(t, bodies, bodies)
	want := [2]LabSampleTimes{
		{StartedAt: samples.core.samples[0].started, CompletedAt: samples.core.samples[0].completed},
		{StartedAt: samples.core.samples[1].started, CompletedAt: samples.core.samples[1].completed},
	}
	beforeJSON := labTestJSON(t, samples)
	beforeComparison := labTestReport(t, samples)
	times, err := samples.SampleTimes()
	if err != nil || times != want {
		t.Fatal("MODEL accessor did not return the opaque capture's exact time values")
	}
	times[0].StartedAt = time.Time{}
	times[0].CompletedAt = want[0].CompletedAt.Add(-time.Hour)
	times[1] = LabSampleTimes{}
	again, err := samples.SampleTimes()
	if err != nil || again != want || !reflect.DeepEqual(labTestReport(t, samples), beforeComparison) ||
		string(labTestJSON(t, samples)) != string(beforeJSON) {
		t.Fatal("MODEL returned time array changed the opaque samples or original comparison")
	}
	var forged LabSamples
	if err := json.Unmarshal(labTestJSON(t, want), &forged); err != ErrLabReadbackInput || forged.core != nil {
		t.Fatal("MODEL public time values became opaque sample authority")
	}
	if result, err := forged.SampleTimes(); err != ErrLabReadbackInput || result != [2]LabSampleTimes{} {
		t.Fatal("MODEL JSON-restored time values exposed usable sample metadata")
	}
}

func TestLabSampleTimesRejectsCorruptSamplesAndTimeOrders(t *testing.T) {
	bodies := labTestBodies(t, false)
	seed := labTestRead(t, bodies, bodies)
	if _, err := seed.SampleTimes(); err != nil {
		t.Fatal("MODEL valid opaque seed rejected before negative cases")
	}
	if result, err := (LabSamples{}).SampleTimes(); err != ErrLabReadbackInput || result != [2]LabSampleTimes{} {
		t.Fatal("MODEL zero samples returned usable time values")
	}
	cases := []struct {
		name string
		edit func(*labSamplesCore)
	}{
		{"seven_requests", func(c *labSamplesCore) { c.requests = 7 }},
		{"nine_requests", func(c *labSamplesCore) { c.requests = 9 }},
		{"first_digest_changed", func(c *labSamplesCore) { c.samples[0].digest = strings.Repeat("0", 64) }},
		{"second_digest_changed", func(c *labSamplesCore) { c.samples[1].digest = strings.Repeat("0", 64) }},
		{"projection_changed_without_digest", func(c *labSamplesCore) { c.samples[1].projection.General = json.RawMessage(`{}`) }},
		{"invalid_projection_json", func(c *labSamplesCore) { c.samples[0].projection.General = json.RawMessage(`{`) }},
		{"first_witness_missing", func(c *labSamplesCore) { c.samples[0].witness = "" }},
		{"second_witness_missing", func(c *labSamplesCore) { c.samples[1].witness = "" }},
		{"first_started_zero", func(c *labSamplesCore) { c.samples[0].started = time.Time{} }},
		{"first_completed_zero", func(c *labSamplesCore) { c.samples[0].completed = time.Time{} }},
		{"second_started_zero", func(c *labSamplesCore) { c.samples[1].started = time.Time{} }},
		{"second_completed_zero", func(c *labSamplesCore) { c.samples[1].completed = time.Time{} }},
		{"first_round_reversed", func(c *labSamplesCore) { c.samples[0].completed = c.samples[0].started.Add(-time.Nanosecond) }},
		{"rounds_overlap", func(c *labSamplesCore) { c.samples[1].started = c.samples[0].completed.Add(-time.Nanosecond) }},
		{"second_round_reversed", func(c *labSamplesCore) { c.samples[1].completed = c.samples[1].started.Add(-time.Nanosecond) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			core := *seed.core
			tc.edit(&core)
			value, err := (LabSamples{core: &core}).SampleTimes()
			if err != ErrLabReadbackInput || value != [2]LabSampleTimes{} {
				t.Fatal("MODEL incomplete or unordered sample returned partial time values")
			}
		})
	}
	if _, err := seed.SampleTimes(); err != nil {
		t.Fatal("MODEL negative cases mutated their original opaque seed")
	}
}

func TestLabSampleTimesDoesNotGrantStabilityOrFreshness(t *testing.T) {
	first := labTestBodies(t, false)
	changedWitness := labTestBodies(t, false)
	changedWitness["/proxies"] = labTestMutate(t, changedWitness["/proxies"], func(m map[string]any) {
		m["proxies"].(map[string]any)["http-a"].(map[string]any)["id"] = "22222222-2222-4222-8222-222222222222"
	})
	for name, second := range map[string]map[string][]byte{
		"projection_changed": labTestBodies(t, true),
		"witness_changed":    changedWitness,
	} {
		t.Run(name, func(t *testing.T) {
			samples := labTestRead(t, first, second)
			if _, err := samples.SampleTimes(); err != nil {
				t.Fatal("MODEL valid time metadata was confused with projection stability")
			}
			if report := labTestReport(t, samples); report.Conclusion != LabProjectionUnstable ||
				report.ObservedProjectionSHA256 != nil || report.FullPayloadProven || report.AuthorizationProven || report.Production {
				t.Fatal("MODEL time accessor changed the original unstable comparison or granted authority")
			}
		})
	}
	seed := labTestRead(t, first, first)
	core := *seed.core
	// White-box metadata boundary cases remain based on a genuine MODEL
	// capture. No JSON constructor or current-clock freshness flag is added.
	old := time.Date(2001, time.January, 1, 0, 0, 0, 0, time.UTC)
	for i := range core.samples {
		core.samples[i].started = old
		core.samples[i].completed = old
	}
	times, err := (LabSamples{core: &core}).SampleTimes()
	want := [2]LabSampleTimes{{StartedAt: old, CompletedAt: old}, {StartedAt: old, CompletedAt: old}}
	if err != nil || times != want {
		t.Fatal("MODEL accessor invented current-clock freshness or rejected equal ordered boundaries")
	}
}
