package proberestore

import (
	"testing"
)

type topologyClass struct {
	name string
	topo func(Journal) Topology
}

var topologyClasses = []topologyClass{
	{"absent-absent", func(Journal) Topology { return Topology{} }},
	{"absent-old", func(j Journal) Topology { return Topology{StagePresent: true, StageSHA256: j.Digests.OldStateSHA256} }},
	{"absent-new", func(j Journal) Topology { return Topology{StagePresent: true, StageSHA256: j.Digests.NewStateSHA256} }},
	{"absent-other", func(Journal) Topology { return Topology{StagePresent: true, StageSHA256: hashOf('f')} }},
	{"old-absent", func(j Journal) Topology { return Topology{LivePresent: true, LiveSHA256: j.Digests.OldStateSHA256} }},
	{"old-old", func(j Journal) Topology {
		return Topology{true, j.Digests.OldStateSHA256, true, j.Digests.OldStateSHA256}
	}},
	{"old-new", func(j Journal) Topology {
		return Topology{true, j.Digests.OldStateSHA256, true, j.Digests.NewStateSHA256}
	}},
	{"old-other", func(j Journal) Topology { return Topology{true, j.Digests.OldStateSHA256, true, hashOf('f')} }},
	{"new-absent", func(j Journal) Topology { return Topology{LivePresent: true, LiveSHA256: j.Digests.NewStateSHA256} }},
	{"new-old", func(j Journal) Topology {
		return Topology{true, j.Digests.NewStateSHA256, true, j.Digests.OldStateSHA256}
	}},
	{"new-new", func(j Journal) Topology {
		return Topology{true, j.Digests.NewStateSHA256, true, j.Digests.NewStateSHA256}
	}},
	{"new-other", func(j Journal) Topology { return Topology{true, j.Digests.NewStateSHA256, true, hashOf('f')} }},
	{"other-absent", func(Journal) Topology { return Topology{LivePresent: true, LiveSHA256: hashOf('f')} }},
	{"other-old", func(j Journal) Topology { return Topology{true, hashOf('f'), true, j.Digests.OldStateSHA256} }},
	{"other-new", func(j Journal) Topology { return Topology{true, hashOf('f'), true, j.Digests.NewStateSHA256} }},
	{"other-other", func(Journal) Topology { return Topology{true, hashOf('f'), true, hashOf('0')} }},
}

func TestRecoveryAllPhasesByAllSixteenTopologies(t *testing.T) {
	if len(topologyClasses) != 16 {
		t.Fatalf("topology class count=%d", len(topologyClasses))
	}
	seen := map[string]bool{}
	for _, tc := range topologyClasses {
		if seen[tc.name] {
			t.Fatalf("duplicate topology class %q", tc.name)
		}
		seen[tc.name] = true
	}
	for _, phase := range Phases() {
		j := journalAt(t, phase)
		for _, tc := range topologyClasses {
			t.Run(string(phase)+"/"+tc.name, func(t *testing.T) {
				got, err := DecideRecovery(j, tc.topo(j))
				if err != nil {
					t.Fatal(err)
				}
				if got.Action == "" || !safeReason.MatchString(got.ReasonCode) {
					t.Fatalf("invalid decision %#v", got)
				}
			})
		}
	}
}

func TestRecoveryIndependentSafetyInvariants(t *testing.T) {
	rollbackRequiredPhases := map[Phase]bool{
		PhaseSwitchArmed:            true,
		PhaseStateExchanged:         true,
		PhaseContainerRecreated:     true,
		PhaseEgressRebound:          true,
		PhaseContainerStarted:       true,
		PhaseLocalHealthPassed:      true,
		PhaseIndependentProbePassed: true,
		PhaseRollbackArmed:          true,
	}
	for _, phase := range Phases() {
		j := journalAt(t, phase)
		for _, tc := range topologyClasses {
			topo := tc.topo(j)
			got, err := DecideRecovery(j, topo)
			if err != nil {
				t.Fatalf("%s/%s: %v", phase, tc.name, err)
			}

			// An exchange rollback is safe only when live is exactly new and
			// stage is exactly old.
			if got.Action == RecoveryRollbackExchange || got.Action == RecoveryContinueRollback {
				if tc.name != "new-old" {
					t.Fatalf("%s/%s: rollback escaped topology gate: %#v", phase, tc.name, got)
				}
			}
			rollbackEligible := rollbackRequiredPhases[phase]
			if rollbackEligible && tc.name == "new-old" && got.Action != RecoveryRollbackExchange && got.Action != RecoveryContinueRollback {
				t.Fatalf("%s/%s: observed exchange did not select rollback: %#v", phase, tc.name, got)
			}

			// Commit acknowledgement is safe only for the terminal committed
			// phase with the new object live and no unknown stage object.
			shouldCommit := phase == PhaseCommitted && (tc.name == "new-old" || tc.name == "new-absent")
			if (got.Action == RecoveryCommitted) != shouldCommit {
				t.Fatalf("%s/%s: commit equivalence violated: %#v", phase, tc.name, got)
			}

			// Runtime restoration always requires direct observation of old live.
			if got.Action == RecoveryRestoreOld && (!topo.LivePresent || topo.LiveSHA256 != j.Digests.OldStateSHA256) {
				t.Fatalf("%s/%s: restore without old live: %#v", phase, tc.name, got)
			}

			// Any present object outside the old/new identity set fails closed.
			unknown := topo.LivePresent && topo.LiveSHA256 != j.Digests.OldStateSHA256 && topo.LiveSHA256 != j.Digests.NewStateSHA256
			unknown = unknown || topo.StagePresent && topo.StageSHA256 != j.Digests.OldStateSHA256 && topo.StageSHA256 != j.Digests.NewStateSHA256
			if unknown {
				want := RecoveryRescueRequired
				if phase == PhaseRescueLockdown {
					want = RecoveryRescueLockdown
				}
				if got.Action != want {
					t.Fatalf("%s/%s: unknown object escaped rescue: %#v", phase, tc.name, got)
				}
			}

			if phase == PhaseRescueRequired && got.Action != RecoveryRescueRequired {
				t.Fatalf("%s escaped to %s", phase, got.Action)
			}
			if phase == PhaseRescueLockdown && got.Action != RecoveryRescueLockdown {
				t.Fatalf("%s escaped to %s", phase, got.Action)
			}
			if phase != PhaseRescueLockdown && got.Action == RecoveryRescueLockdown {
				t.Fatalf("%s/%s falsely claimed verified lockdown", phase, tc.name)
			}
		}
	}
}

func TestRecoveryPositiveContractsAndReasonCodes(t *testing.T) {
	tests := []struct {
		phase  Phase
		topo   string
		action RecoveryAction
		reason string
	}{
		{PhaseNew, "old-absent", RecoveryRestoreOld, "PRE_SWITCH_OLD_LIVE"},
		{PhaseSwitchArmed, "old-new", RecoveryRestoreOld, "SWITCH_ARMED_UNEXCHANGED"},
		{PhaseSwitchArmed, "new-old", RecoveryRollbackExchange, "ARMED_EXCHANGE_OBSERVED"},
		{PhaseSwitchArmed, "old-absent", RecoveryRescueRequired, "PRE_SWITCH_TOPOLOGY_CONTRADICTION"},
		{PhaseStateExchanged, "new-old", RecoveryRollbackExchange, "POST_SWITCH_ROLLBACK_REQUIRED"},
		{PhaseRollbackArmed, "new-old", RecoveryContinueRollback, "ROLLBACK_PENDING"},
		{PhaseRollbackArmed, "old-new", RecoveryRestoreOld, "ROLLBACK_EXCHANGE_OBSERVED"},
		{PhaseCommitted, "new-absent", RecoveryCommitted, "COMMITTED_NEW_LIVE"},
		{PhaseRolledBack, "old-absent", RecoveryRestoreOld, "ROLLED_BACK_OLD_LIVE"},
		{PhaseFailed, "old-absent", RecoveryRestoreOld, "FAILED_WITH_OLD_LIVE"},
		{PhaseRescueRequired, "old-new", RecoveryRescueRequired, "LOCKDOWN_MUST_BE_VERIFIED"},
		{PhaseRescueLockdown, "old-new", RecoveryRescueLockdown, "RESCUE_PHASE_FAIL_CLOSED"},
	}
	byName := map[string]topologyClass{}
	for _, tc := range topologyClasses {
		byName[tc.name] = tc
	}
	for _, tt := range tests {
		t.Run(string(tt.phase)+"/"+tt.topo, func(t *testing.T) {
			j := journalAt(t, tt.phase)
			got, err := DecideRecovery(j, byName[tt.topo].topo(j))
			if err != nil {
				t.Fatal(err)
			}
			if got.Action != tt.action || got.ReasonCode != tt.reason {
				t.Fatalf("got %#v want action=%s reason=%s", got, tt.action, tt.reason)
			}
		})
	}
}

func TestRecoveryRejectsDigestWhenObjectAbsent(t *testing.T) {
	j := validJournal(t)
	for _, topo := range []Topology{
		{LiveSHA256: j.Digests.OldStateSHA256},
		{StageSHA256: j.Digests.NewStateSHA256},
	} {
		if _, err := DecideRecovery(j, topo); err == nil {
			t.Fatalf("impossible topology accepted: %#v", topo)
		}
	}
}
