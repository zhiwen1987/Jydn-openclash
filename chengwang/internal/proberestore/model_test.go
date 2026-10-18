package proberestore

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func hashOf(ch byte) string { return strings.Repeat(string(ch), 64) }
func validJournal(t *testing.T) Journal {
	t.Helper()
	j, err := New("restore-01", Identity{"site-a", "probe-a", "backup-01"}, Digests{hashOf('a'), hashOf('b'), hashOf('c'), hashOf('d')}, time.Date(2026, 10, 19, 1, 2, 3, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	return j
}
func requestFor(j Journal, to Phase) TransitionRequest {
	reason := "ADVANCE"
	if to == PhaseRescueLockdown {
		reason = "LOCKDOWN_VERIFIED"
	}
	r := TransitionRequest{To: to, ReasonCode: reason, EvidenceSHA256: hashOf('e'), At: j.UpdatedAt.Add(time.Second)}
	switch to {
	case PhaseSwitchArmed:
		r.Topology = &Topology{true, j.Digests.OldStateSHA256, true, j.Digests.NewStateSHA256}
	case PhaseStateExchanged, PhaseRollbackArmed:
		r.Topology = &Topology{true, j.Digests.NewStateSHA256, true, j.Digests.OldStateSHA256}
	case PhaseStateRollbackExchanged:
		r.Topology = &Topology{true, j.Digests.OldStateSHA256, true, j.Digests.NewStateSHA256}
	case PhaseFailed:
		if j.Phase == PhaseSwitchArmed {
			r.Topology = &Topology{true, j.Digests.OldStateSHA256, true, j.Digests.NewStateSHA256}
		}
	}
	return r
}
func advance(t *testing.T, j Journal, to Phase) Journal {
	t.Helper()
	n, err := j.Transition(requestFor(j, to))
	if err != nil {
		t.Fatalf("%s -> %s: %v", j.Phase, to, err)
	}
	return n
}
func pathTo(target Phase) ([]Phase, bool) {
	if target == PhaseNew {
		return nil, true
	}
	type node struct {
		p    Phase
		path []Phase
	}
	q := []node{{PhaseNew, nil}}
	seen := map[Phase]bool{PhaseNew: true}
	for len(q) > 0 {
		n := q[0]
		q = q[1:]
		for _, next := range allPhases {
			if !CanTransition(n.p, next) || seen[next] {
				continue
			}
			p := append(append([]Phase{}, n.path...), next)
			if next == target {
				return p, true
			}
			seen[next] = true
			q = append(q, node{next, p})
		}
	}
	return nil, false
}
func journalAt(t *testing.T, p Phase) Journal {
	t.Helper()
	j := validJournal(t)
	path, ok := pathTo(p)
	if !ok {
		t.Fatalf("no path to %s", p)
	}
	for _, next := range path {
		j = advance(t, j, next)
	}
	return j
}

func TestTransitionMatrixExhaustive(t *testing.T) {
	for _, from := range Phases() {
		for _, to := range Phases() {
			j := journalAt(t, from)
			_, err := j.Transition(requestFor(j, to))
			if CanTransition(from, to) != (err == nil) {
				t.Fatalf("%s -> %s allowed=%v err=%v", from, to, CanTransition(from, to), err)
			}
		}
	}
}
func TestSwitchArmedCannotDirectlyArmRollback(t *testing.T) {
	if CanTransition(PhaseSwitchArmed, PhaseRollbackArmed) {
		t.Fatal("unsafe direct rollback arm remains")
	}
}
func TestAllNonGenesisEventsRequireEvidence(t *testing.T) {
	j := validJournal(t)
	r := requestFor(j, PhaseLocked)
	r.EvidenceSHA256 = ""
	if _, err := j.Transition(r); !errors.Is(err, ErrInvalidJournal) {
		t.Fatalf("err=%v", err)
	}
	j = advance(t, j, PhaseLocked)
	j.Events[1].EvidenceSHA256 = ""
	if j.Validate() == nil {
		t.Fatal("missing persisted evidence accepted")
	}
}
func TestExchangeTransitionsRequireExactTopology(t *testing.T) {
	j := journalAt(t, PhaseStagedValidated)
	r := requestFor(j, PhaseSwitchArmed)
	r.Topology = nil
	if _, err := j.Transition(r); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("nil topology err=%v", err)
	}
	r = requestFor(j, PhaseSwitchArmed)
	r.Topology.LiveSHA256 = j.Digests.NewStateSHA256
	if _, err := j.Transition(r); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("wrong topology err=%v", err)
	}
}
func TestRescueRequiresTwoStatesAndLockdownEvidence(t *testing.T) {
	j := validJournal(t)
	if _, err := j.Transition(TransitionRequest{To: PhaseRescueLockdown, ReasonCode: "LOCKDOWN_VERIFIED", EvidenceSHA256: hashOf('e'), At: j.UpdatedAt.Add(time.Second)}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("direct lockdown=%v", err)
	}
	j = advance(t, j, PhaseRescueRequired)
	r := requestFor(j, PhaseRescueLockdown)
	r.ReasonCode = "ADVANCE"
	if _, err := j.Transition(r); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("unverified lockdown=%v", err)
	}
	j = advance(t, j, PhaseRescueLockdown)
	if !IsTerminal(j.Phase) {
		t.Fatal("lockdown not terminal")
	}
}
func TestClockRollbackAndUnsafeReasonRejected(t *testing.T) {
	j := validJournal(t)
	r := requestFor(j, PhaseLocked)
	r.At = j.UpdatedAt.Add(-time.Nanosecond)
	if _, err := j.Transition(r); !errors.Is(err, ErrClockRollback) {
		t.Fatalf("clock=%v", err)
	}
	r = requestFor(j, PhaseLocked)
	r.ReasonCode = "token=secret"
	if _, err := j.Transition(r); !errors.Is(err, ErrInvalidJournal) {
		t.Fatalf("reason=%v", err)
	}
}
func TestValidateDetectsTamperingAndTruncation(t *testing.T) {
	j := advance(t, validJournal(t), PhaseLocked)
	cases := map[string]func(*Journal){"hash": func(v *Journal) { v.Events[1].Hash = hashOf('f') }, "evidence": func(v *Journal) { v.Events[1].EvidenceSHA256 = hashOf('f') }, "phase": func(v *Journal) { v.Phase = PhaseCommitted }, "sequence": func(v *Journal) { v.Sequence++ }, "truncate": func(v *Journal) { v.Events = v.Events[:1] }, "immutable": func(v *Journal) { v.Digests.OldStateSHA256 = hashOf('f') }}
	for n, m := range cases {
		t.Run(n, func(t *testing.T) {
			v := j
			v.Events = append([]Event(nil), j.Events...)
			m(&v)
			if v.Validate() == nil {
				t.Fatal("tamper accepted")
			}
		})
	}
}
func TestNewRejectsBadIdentityAndEqualDigests(t *testing.T) {
	id := Identity{"site-a", "probe-a", "backup-a"}
	d := Digests{hashOf('a'), hashOf('b'), hashOf('c'), hashOf('d')}
	if _, err := New("BAD ID", id, d, time.Now()); err == nil {
		t.Fatal("bad id")
	}
	d.NewStateSHA256 = d.OldStateSHA256
	if _, err := New("restore-a", id, d, time.Now()); err == nil {
		t.Fatal("equal digest")
	}
}
