package mihomodeploy

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

// This is a structural MODEL, not an issued route or recovery capability. The
// real receipt is available only after the source-owned loopback HTTP path.
func labRecoveryMarkerBoundsModel(t *testing.T, role string) labRecoveryLocalMarkerValue {
	t.Helper()
	nonce := strings.Repeat("c", 64)
	marker := labLocalMarker(role, nonce)
	before := []labLocalCounter{
		{Role: "A", ConnectIngress: 3, TunnelRequests: 5, ForwardInvocations: 7, OriginRequests: 11, Rejected: 13},
		{Role: "B", ConnectIngress: 17, TunnelRequests: 19, ForwardInvocations: 23, OriginRequests: 29, Rejected: 31},
		{Role: "origin", ConnectIngress: 37, TunnelRequests: 41, ForwardInvocations: 43, OriginRequests: 47, Rejected: 53},
	}
	after := append([]labLocalCounter(nil), before...)
	for i := range after {
		if after[i].Role == role {
			after[i].ConnectIngress++
			after[i].TunnelRequests++
			after[i].ForwardInvocations++
			after[i].OriginRequests++
		}
		if after[i].Role == "origin" {
			after[i].OriginRequests++
		}
	}
	started := time.Date(2026, time.October, 25, 12, 0, 0, 0, time.UTC)
	v := labRecoveryLocalMarkerValue{
		Schema:                 "chengwang.mihomo-recovery-local-marker/v1",
		Scope:                  labRecoveryLocalScope,
		ExpectedRole:           role,
		ExpectedMarkerSHA256:   labConfigHash(marker),
		ExpectedMarkerBytes:    len(marker),
		StartedAt:              started,
		ReturnedAt:             started.Add(time.Millisecond),
		HandlerCompleted:       true,
		ClientNaturalEOF:       true,
		ProxyNaturalEOF:        true,
		OriginWriteComplete:    true,
		LocalProxyMarkerProven: true,
		Route: labLocalRoute{
			Phase:          labRecoveryLocalPhase,
			NonceSHA256:    labConfigHash([]byte(nonce)),
			ClientResponse: labLocalObserved(marker),
			ProxyResponse:  labLocalObserved(marker),
			OriginResponse: labLocalObserved(marker),
			CountersBefore: before,
			CountersAfter:  after,
			Matched:        true,
		},
	}
	if !labRecoveryMarkerValueValid(v) {
		t.Fatal("structural MODEL positive control rejected; this is not an issued receipt")
	}
	return v
}

// Independent copy for mutation tests: a broken production clone must not hide
// aliasing or let one negative case contaminate another case's positive control.
func labRecoveryMarkerBoundsCopy(v labRecoveryLocalMarkerValue) labRecoveryLocalMarkerValue {
	if v.Route.ClientResponse != nil {
		p := *v.Route.ClientResponse
		v.Route.ClientResponse = &p
	}
	if v.Route.ProxyResponse != nil {
		p := *v.Route.ProxyResponse
		v.Route.ProxyResponse = &p
	}
	if v.Route.OriginResponse != nil {
		p := *v.Route.OriginResponse
		v.Route.OriginResponse = &p
	}
	v.Route.CountersBefore = append([]labLocalCounter(nil), v.Route.CountersBefore...)
	v.Route.CountersAfter = append([]labLocalCounter(nil), v.Route.CountersAfter...)
	return v
}

func labRecoveryMarkerBoundsFields(c *labLocalCounter) []*int {
	return []*int{&c.ConnectIngress, &c.TunnelRequests, &c.ForwardInvocations, &c.OriginRequests, &c.Rejected}
}

func labRecoveryMarkerBoundsReject(t *testing.T, original labRecoveryLocalMarkerValue, mutate func(*labRecoveryLocalMarkerValue)) {
	t.Helper()
	v := labRecoveryMarkerBoundsCopy(original)
	mutate(&v)
	if labRecoveryMarkerValueValid(v) {
		t.Fatal("inconsistent marker MODEL accepted")
	}
	if !labRecoveryMarkerValueValid(original) {
		t.Fatal("negative mutation changed the structural positive control")
	}
}

func TestLabRecoveryMarkerBoundsMatchedRequiresThreeCompleteBoundBodies(t *testing.T) {
	for _, role := range []string{"A", "B"} {
		t.Run(role, func(t *testing.T) {
			original := labRecoveryMarkerBoundsModel(t, role)
			for bodyIndex := 0; bodyIndex < 3; bodyIndex++ {
				for _, damage := range []string{"missing", "incomplete", "hash", "bytes"} {
					t.Run(fmt.Sprintf("body-%d-%s", bodyIndex, damage), func(t *testing.T) {
						labRecoveryMarkerBoundsReject(t, original, func(v *labRecoveryLocalMarkerValue) {
							bodies := []**labLocalBody{&v.Route.ClientResponse, &v.Route.ProxyResponse, &v.Route.OriginResponse}
							switch damage {
							case "missing":
								*bodies[bodyIndex] = nil
							case "incomplete":
								(*bodies[bodyIndex]).Complete = false
							case "hash":
								(*bodies[bodyIndex]).SHA256 = strings.Repeat("d", 64)
							case "bytes":
								(*bodies[bodyIndex]).Bytes++
							}
						})
					})
				}
			}
			for name, mutate := range map[string]func(*labRecoveryLocalMarkerValue){
				"matched-only": func(v *labRecoveryLocalMarkerValue) {
					v.Route.ClientResponse, v.Route.ProxyResponse, v.Route.OriginResponse = nil, nil, nil
				},
				"all-bodies-consistent-but-not-expected": func(v *labRecoveryLocalMarkerValue) {
					v.Route.ClientResponse.SHA256 = strings.Repeat("d", 64)
					v.Route.ProxyResponse.SHA256 = strings.Repeat("d", 64)
					v.Route.OriginResponse.SHA256 = strings.Repeat("d", 64)
				},
				"not-matched":  func(v *labRecoveryLocalMarkerValue) { v.Route.Matched = false },
				"empty-hash":   func(v *labRecoveryLocalMarkerValue) { v.ExpectedMarkerSHA256 = "" },
				"zero-hash":    func(v *labRecoveryLocalMarkerValue) { v.ExpectedMarkerSHA256 = strings.Repeat("0", 64) },
				"empty-marker": func(v *labRecoveryLocalMarkerValue) { v.ExpectedMarkerBytes = 0 },
				"negative-size": func(v *labRecoveryLocalMarkerValue) {
					v.ExpectedMarkerBytes = -1
				},
				"oversized-marker": func(v *labRecoveryLocalMarkerValue) { v.ExpectedMarkerBytes = 4097 },
			} {
				t.Run(name, func(t *testing.T) { labRecoveryMarkerBoundsReject(t, original, mutate) })
			}
		})
	}
}

func TestLabRecoveryMarkerBoundsNonceAndMarkerDTOCannotIssueReceipt(t *testing.T) {
	original := labRecoveryMarkerBoundsModel(t, "A")
	for _, name := range []string{"roundtrip-value", "different-nonzero-nonce", "coordinated-marker-and-bodies"} {
		t.Run(name, func(t *testing.T) {
			v := labRecoveryMarkerBoundsCopy(original)
			switch name {
			case "roundtrip-value":
				raw, err := json.Marshal(v)
				if err != nil || json.Unmarshal(raw, &v) != nil {
					t.Fatal("structural value JSON roundtrip failed")
				}
			case "different-nonzero-nonce":
				v.Route.NonceSHA256 = strings.Repeat("e", 64)
			case "coordinated-marker-and-bodies":
				nonce := strings.Repeat("f", 64)
				marker := labLocalMarker("A", nonce)
				v.Route.NonceSHA256 = labConfigHash([]byte(nonce))
				v.ExpectedMarkerSHA256, v.ExpectedMarkerBytes = labConfigHash(marker), len(marker)
				v.Route.ClientResponse = labLocalObserved(marker)
				v.Route.ProxyResponse = labLocalObserved(marker)
				v.Route.OriginResponse = labLocalObserved(marker)
			}
			// Hash-only DTO consistency cannot prove nonce preimage provenance.
			// All three are valid metadata; none may mint a source-issued receipt.
			if !labRecoveryMarkerValueValid(v) {
				t.Fatal("structurally consistent DTO unexpectedly rejected")
			}
			f := newLabLocalFixture("model-A", "model-B")
			receipt := &labRecoveryMarkerReceipt{owner: f, value: v}
			out, err := f.consumeRecoveryReceipt(context.Background(), receipt, v.Route)
			if err == nil || !reflect.DeepEqual(out, labRecoveryLocalMarkerValue{}) || len(f.recoveryReceipts) != 0 {
				t.Fatal("DTO minted a receipt or escaped as accepted evidence")
			}
			if _, err := json.Marshal(receipt); err == nil {
				t.Fatal("private receipt serialized")
			}
			var decoded labRecoveryMarkerReceipt
			if json.Unmarshal([]byte(`{"value":{"Matched":true}}`), &decoded) == nil {
				t.Fatal("JSON minted private receipt")
			}
		})
	}
	for _, hash := range []string{"", strings.Repeat("0", 64), strings.Repeat("g", 64), strings.Repeat("a", 63)} {
		t.Run("bad-nonce-"+hash, func(t *testing.T) {
			labRecoveryMarkerBoundsReject(t, original, func(v *labRecoveryLocalMarkerValue) { v.Route.NonceSHA256 = hash })
		})
	}
}

func TestLabRecoveryMarkerBoundsCounterRolesAreExactAndOrdered(t *testing.T) {
	original := labRecoveryMarkerBoundsModel(t, "A")
	for _, side := range []string{"before", "after", "both"} {
		for _, damage := range []string{"nil", "missing", "extra", "duplicate", "reordered", "unknown", "case"} {
			t.Run(side+"-"+damage, func(t *testing.T) {
				labRecoveryMarkerBoundsReject(t, original, func(v *labRecoveryLocalMarkerValue) {
					mutate := func(counters *[]labLocalCounter) {
						switch damage {
						case "nil":
							*counters = nil
						case "missing":
							*counters = (*counters)[:2]
						case "extra":
							*counters = append(*counters, labLocalCounter{Role: "extra"})
						case "duplicate":
							(*counters)[1].Role = "A"
						case "reordered":
							(*counters)[0], (*counters)[1] = (*counters)[1], (*counters)[0]
						case "unknown":
							(*counters)[2].Role = "upstream"
						case "case":
							(*counters)[0].Role = "a"
						}
					}
					if side != "after" {
						mutate(&v.Route.CountersBefore)
					}
					if side != "before" {
						mutate(&v.Route.CountersAfter)
					}
				})
			})
		}
	}
}

func TestLabRecoveryMarkerBoundsSelectedAndUnselectedDeltasStayExact(t *testing.T) {
	for _, role := range []string{"A", "B"} {
		original := labRecoveryMarkerBoundsModel(t, role)
		for counterIndex := 0; counterIndex < 3; counterIndex++ {
			for fieldIndex := 0; fieldIndex < 5; fieldIndex++ {
				for _, change := range []int{-1, 1} {
					t.Run(fmt.Sprintf("%s-role-%d-field-%d-change-%d", role, counterIndex, fieldIndex, change), func(t *testing.T) {
						labRecoveryMarkerBoundsReject(t, original, func(v *labRecoveryLocalMarkerValue) {
							fields := labRecoveryMarkerBoundsFields(&v.Route.CountersAfter[counterIndex])
							*fields[fieldIndex] += change
						})
					})
				}
			}
		}
		t.Run(role+"-wrong-selected-role", func(t *testing.T) {
			labRecoveryMarkerBoundsReject(t, original, func(v *labRecoveryLocalMarkerValue) {
				if role == "A" {
					v.ExpectedRole = "B"
				} else {
					v.ExpectedRole = "A"
				}
			})
		})
	}
}

func TestLabRecoveryMarkerBoundsTimesRolesFlagsAndNonnegativeCountersFailClosed(t *testing.T) {
	original := labRecoveryMarkerBoundsModel(t, "A")
	for name, mutate := range map[string]func(*labRecoveryLocalMarkerValue){
		"schema":        func(v *labRecoveryLocalMarkerValue) { v.Schema += "-unknown" },
		"scope":         func(v *labRecoveryLocalMarkerValue) { v.Scope = "INTERNET_BUSINESS" },
		"phase":         func(v *labRecoveryLocalMarkerValue) { v.Route.Phase = "SERVICE_NEW" },
		"origin-role":   func(v *labRecoveryLocalMarkerValue) { v.ExpectedRole = "origin" },
		"unknown-role":  func(v *labRecoveryLocalMarkerValue) { v.ExpectedRole = "C" },
		"zero-start":    func(v *labRecoveryLocalMarkerValue) { v.StartedAt = time.Time{} },
		"zero-return":   func(v *labRecoveryLocalMarkerValue) { v.ReturnedAt = time.Time{} },
		"reversed-time": func(v *labRecoveryLocalMarkerValue) { v.ReturnedAt = v.StartedAt.Add(-time.Nanosecond) },
		"non-utc-start": func(v *labRecoveryLocalMarkerValue) {
			v.StartedAt = v.StartedAt.In(time.FixedZone("model-offset", 3600))
		},
		"non-utc-return": func(v *labRecoveryLocalMarkerValue) {
			v.ReturnedAt = v.ReturnedAt.In(time.FixedZone("model-offset", 3600))
		},
		"handler":      func(v *labRecoveryLocalMarkerValue) { v.HandlerCompleted = false },
		"client-eof":   func(v *labRecoveryLocalMarkerValue) { v.ClientNaturalEOF = false },
		"proxy-eof":    func(v *labRecoveryLocalMarkerValue) { v.ProxyNaturalEOF = false },
		"origin-write": func(v *labRecoveryLocalMarkerValue) { v.OriginWriteComplete = false },
		"local-proven": func(v *labRecoveryLocalMarkerValue) { v.LocalProxyMarkerProven = false },
	} {
		t.Run(name, func(t *testing.T) { labRecoveryMarkerBoundsReject(t, original, mutate) })
	}
	deadline := original.ReturnedAt.Add(time.Second)
	if !labRecoveryMarkerWindow(original, original.StartedAt, original.ReturnedAt, deadline) {
		t.Fatal("inclusive start/return structural window positive control rejected")
	}
	for _, tc := range []struct {
		name     string
		earliest time.Time
		observed time.Time
		deadline time.Time
	}{
		{"start-before-entry", original.StartedAt.Add(time.Nanosecond), original.ReturnedAt, deadline},
		{"return-after-observation", original.StartedAt, original.ReturnedAt.Add(-time.Nanosecond), deadline},
		{"observation-at-deadline", original.StartedAt, original.ReturnedAt, original.ReturnedAt},
		{"observation-after-deadline", original.StartedAt, original.ReturnedAt, original.ReturnedAt.Add(-time.Nanosecond)},
		{"missing-entry", time.Time{}, original.ReturnedAt, deadline},
		{"missing-observation", original.StartedAt, time.Time{}, deadline},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if labRecoveryMarkerWindow(original, tc.earliest, tc.observed, tc.deadline) {
				t.Fatal("out-of-window MODEL admitted")
			}
		})
	}
	maxInt := int(^uint(0) >> 1)
	minInt := -maxInt - 1
	for counterIndex := 0; counterIndex < 3; counterIndex++ {
		for fieldIndex := 0; fieldIndex < 5; fieldIndex++ {
			for _, damage := range []string{"negative-before", "negative-after", "both-negative", "wrapped-decrement", "wrapped-increment", "huge-delta"} {
				t.Run(fmt.Sprintf("counter-%d-field-%d-%s", counterIndex, fieldIndex, damage), func(t *testing.T) {
					labRecoveryMarkerBoundsReject(t, original, func(v *labRecoveryLocalMarkerValue) {
						before := labRecoveryMarkerBoundsFields(&v.Route.CountersBefore[counterIndex])[fieldIndex]
						after := labRecoveryMarkerBoundsFields(&v.Route.CountersAfter[counterIndex])[fieldIndex]
						switch damage {
						case "negative-before":
							*before = -1
						case "negative-after":
							*after = -1
						case "both-negative":
							*before, *after = -2, -1
						case "wrapped-decrement":
							*before, *after = maxInt, minInt
						case "wrapped-increment":
							*before, *after = minInt, maxInt
						case "huge-delta":
							*before, *after = 0, maxInt
						}
					})
				})
			}
		}
	}
}

func TestLabRecoveryMarkerBoundsUnissuedCopiedCrossFixtureAndClosedReceiptsReject(t *testing.T) {
	v := labRecoveryMarkerBoundsModel(t, "A")
	f := newLabLocalFixture("model-A", "model-B")
	other := newLabLocalFixture("model-A", "model-B")
	unissued := &labRecoveryMarkerReceipt{owner: f, value: labRecoveryMarkerBoundsCopy(v)}
	copied := *unissued
	closed := newLabLocalFixture("model-A", "model-B")
	closed.stop() // Empty fixture: exercises real close state without a listener.
	closedReceipt := &labRecoveryMarkerReceipt{owner: closed, value: labRecoveryMarkerBoundsCopy(v)}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		name    string
		fixture *labLocalFixture
		receipt *labRecoveryMarkerReceipt
		ctx     context.Context
	}{
		{"nil-fixture", nil, unissued, context.Background()},
		{"nil-receipt", f, nil, context.Background()},
		{"unissued", f, unissued, context.Background()},
		{"unissued-retry", f, unissued, context.Background()},
		{"copied-unissued", f, &copied, context.Background()},
		{"cross-fixture", other, unissued, context.Background()},
		{"closed-empty-fixture", closed, closedReceipt, context.Background()},
		{"canceled-unissued", f, unissued, canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := tc.fixture.consumeRecoveryReceipt(tc.ctx, tc.receipt, v.Route)
			if err == nil || !reflect.DeepEqual(out, labRecoveryLocalMarkerValue{}) {
				t.Fatal("unissued receipt produced accepted or nonzero evidence")
			}
			if len(f.recoveryReceipts) != 0 || len(other.recoveryReceipts) != 0 || len(closed.recoveryReceipts) != 0 {
				t.Fatal("negative receipt path inserted a capability")
			}
		})
	}
	// None of these is a genuine issued-receipt one-use/close proof. That
	// positive chain requires the actual source-owned HTTP experiment.
}
