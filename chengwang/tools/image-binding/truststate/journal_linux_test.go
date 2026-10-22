//go:build linux

package truststate

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func d7Operation(f stateFixture, id, kind string, raw []byte) Operation {
	data := map[string]string{"catalogueSHA256": hash(raw)}
	if kind == "verify" {
		data = map[string]string{"policyId": "fixture-policy", "approvalSHA256": hash(f.approval), "bundleSHA256": hash([]byte("bundle")), "rootSHA256": hash([]byte("root"))}
	}
	return Operation{ID: id, ActorID: "fixture-actor", ScopeSHA256: hash([]byte("fixed-scope")), Kind: kind, Data: data, AuditBaseHash: strings.Repeat("0", 64)}
}
func d7Prepare(t *testing.T, s *Store, op Operation) {
	t.Helper()
	if err := s.PrepareOperation(context.Background(), op); err != nil {
		t.Fatal(err)
	}
	if err := s.BindPreparedAudit(context.Background(), op.ID, strings.TrimPrefix(hash([]byte("prepared-audit")), "sha256:")); err != nil {
		t.Fatal(err)
	}
}
func d7Entries(t *testing.T, s *Store) []JournalEntry {
	t.Helper()
	j, err := s.Journal(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return j
}

func TestProductTrustStateD7AtomicVerifyOutcomeAndAcknowledgement(t *testing.T) {
	f := newStateFixture(t)
	s, path := createFixture(t, f)
	ctx := context.Background()
	op := d7Operation(f, strings.Repeat("1", 32), "verify", nil)
	d7Prepare(t, s, op)
	bound := &SourceBound{Generation: 1, CatalogueSHA256: hash(f.initial), FreshUntilUnixNano: time.Now().Add(time.Minute).UnixNano()}
	ticket, err := s.BeginTracked(ctx, "fixture-policy", f.approval, op.ID, bound)
	if err != nil {
		t.Fatal(err)
	}
	bound.Generation = 99
	bound.FreshUntilUnixNano = 1 // caller mutation cannot alter the ticket.
	if e := d7Entries(t, s)[0]; e.State != "RESERVED" || e.Outcome != "" || e.GrantID != ticket.GrantID() {
		t.Fatal("reservation and journal were not atomic")
	}
	evidenceHash := hash([]byte("consumption-evidence"))
	if err = s.Complete(ctx, ticket, evidenceHash); err != nil {
		t.Fatal(err)
	}
	e := d7Entries(t, s)[0]
	if e.State != "CONSUMED" || e.Outcome != OutcomeVerificationConsumed || e.EvidenceSHA256 != evidenceHash || e.OutcomeData["evidenceSHA256"] != evidenceHash {
		t.Fatal("consumption and outcome were not atomic")
	}
	if err = s.FinishOperation(ctx, op.ID, OutcomeRejected, nil); err == nil {
		t.Fatal("caller downgraded consumed fact")
	}
	if err = s.FinishOperation(ctx, op.ID, OutcomeVerificationConsumed, nil); err != nil {
		t.Fatal("idempotent observed consumption", err)
	}
	ack := strings.TrimPrefix(hash([]byte("result-audit")), "sha256:")
	if err = s.AcknowledgeOperation(ctx, op.ID, ack); err != nil {
		t.Fatal(err)
	}
	if err = s.AcknowledgeOperation(ctx, op.ID, ack); err != nil {
		t.Fatal("ack idempotence", err)
	}
	if err = s.AcknowledgeOperation(ctx, op.ID, strings.Repeat("f", 64)); !errors.Is(err, ErrReplay) {
		t.Fatal("ack event hash was replaced")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	r, err := Open(ctx, path, f.anchor)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	e = d7Entries(t, r)[0]
	if !e.Acknowledged || e.ResultAuditHash != ack || e.State != "CONSUMED" {
		t.Fatal("ack/outcome missing after reopen")
	}
	if _, err = r.Begin(ctx, "fixture-policy", f.approval); !errors.Is(err, ErrReplay) {
		t.Fatal("journal ack revived signed grant")
	}
}

func TestProductTrustStateD7AtomicUpdateRequiresPreparedAudit(t *testing.T) {
	f := newStateFixture(t)
	s, _ := createFixture(t, f)
	ctx := context.Background()
	doc := f.document
	doc.Generation = 2
	raw := f.sign(t, doc)
	op := d7Operation(f, strings.Repeat("2", 32), "update", raw)
	if err := s.PrepareOperation(ctx, op); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateTracked(ctx, raw, op.ID); err == nil {
		t.Fatal("mutation preceded prepared audit binding")
	}
	if err := s.BindPreparedAudit(ctx, op.ID, strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateTracked(ctx, raw, op.ID); err != nil {
		t.Fatal(err)
	}
	e := d7Entries(t, s)[0]
	state, err := s.Inspect(ctx)
	if err != nil || state.Catalogue.Generation != 2 || e.State != "COMMITTED" || e.Outcome != OutcomeCatalogueCommitted || e.CatalogueSHA256 != hash(raw) || e.Generation != 2 {
		t.Fatal("catalogue and journal diverged")
	}
	if err = s.UpdateTracked(ctx, raw, op.ID); err == nil {
		t.Fatal("operation replayed")
	}
	if err = s.FinishOperation(ctx, op.ID, OutcomeCatalogueCommitted, nil); err != nil {
		t.Fatal(err)
	}
	if err = s.FinishOperation(ctx, op.ID, OutcomeVerificationConsumed, nil); err == nil {
		t.Fatal("update fabricated verification outcome")
	}
}

func TestProductTrustStateD7FreshnessBoundBeforeReservation(t *testing.T) {
	for _, kind := range []string{"generation", "digest", "expired", "beyond-catalogue"} {
		t.Run(kind, func(t *testing.T) {
			f := newStateFixture(t)
			s, _ := createFixture(t, f)
			op := d7Operation(f, strings.Repeat("3", 32), "verify", nil)
			d7Prepare(t, s, op)
			bound := &SourceBound{Generation: 1, CatalogueSHA256: hash(f.initial), FreshUntilUnixNano: time.Now().Add(time.Minute).UnixNano()}
			switch kind {
			case "generation":
				bound.Generation = 2
			case "digest":
				bound.CatalogueSHA256 = hash([]byte("wrong-catalogue"))
			case "expired":
				bound.FreshUntilUnixNano = time.Now().Add(-time.Second).UnixNano()
			case "beyond-catalogue":
				bound.FreshUntilUnixNano = time.Unix(f.document.NotAfterUnix+1, 0).UnixNano()
			}
			if _, err := s.BeginTracked(context.Background(), "fixture-policy", f.approval, op.ID, bound); err == nil {
				t.Fatal("invalid freshness bound burned grant")
			}
			state, err := s.Inspect(context.Background())
			if err != nil || state.LedgerUsed != 0 || d7Entries(t, s)[0].State != "PREPARED" {
				t.Fatal("failed precondition changed signed grant")
			}
		})
	}
}

func TestProductTrustStateD7InterruptedReservationNeverResumes(t *testing.T) {
	f := newStateFixture(t)
	s, path := createFixture(t, f)
	ctx := context.Background()
	op := d7Operation(f, strings.Repeat("4", 32), "verify", nil)
	d7Prepare(t, s, op)
	ticket, err := s.BeginTracked(ctx, "fixture-policy", f.approval, op.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.FinishOperation(ctx, op.ID, OutcomeVerificationConsumed, nil); err == nil {
		t.Fatal("recovery forged successful consumption")
	}
	if err = s.FinishOperation(ctx, op.ID, OutcomeVerificationReserved, nil); err != nil {
		t.Fatal(err)
	}
	if err = s.Complete(ctx, ticket, hash([]byte("late-work"))); err == nil {
		t.Fatal("interrupted operation resumed")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	r, err := Open(ctx, path, f.anchor)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err = r.Begin(ctx, "fixture-policy", f.approval); !errors.Is(err, ErrReplay) {
		t.Fatal("recovery released reservation")
	}
	e := d7Entries(t, r)[0]
	if e.State != "RESERVED" || e.Outcome != OutcomeVerificationReserved {
		t.Fatal("recovery did not preserve interrupted fact")
	}
}

func TestProductTrustStateD7IntentCopiesAndRejectsForgedOutcomes(t *testing.T) {
	f := newStateFixture(t)
	s, _ := createFixture(t, f)
	ctx := context.Background()
	op := d7Operation(f, strings.Repeat("5", 32), "verify", nil)
	d7Prepare(t, s, op)
	op.Data["policyId"] = "tampered"
	j := d7Entries(t, s)
	j[0].Operation.Data["policyId"] = "also-tampered"
	if d7Entries(t, s)[0].Operation.Data["policyId"] != "fixture-policy" {
		t.Fatal("mutable intent map")
	}
	if err := s.FinishOperation(ctx, op.ID, OutcomeVerificationConsumed, nil); err == nil {
		t.Fatal("intent became consumed by enum")
	}
	if err := s.AcknowledgeOperation(ctx, op.ID, strings.Repeat("a", 64)); err == nil {
		t.Fatal("unfinished intent acknowledged")
	}
	if err := s.FinishOperation(ctx, op.ID, OutcomeInterrupted, map[string]string{"code": "PROCESS_INTERRUPTED"}); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishOperation(ctx, op.ID, OutcomeRejected, nil); err == nil {
		t.Fatal("terminal fact rewritten")
	}
	bad := d7Operation(f, strings.Repeat("6", 32), "verify", nil)
	bad.Data["token"] = "must-not-be-stored"
	if err := s.PrepareOperation(ctx, bad); err == nil {
		t.Fatal("secret-bearing journal data accepted")
	}
	if _, err := s.Journal(nil); err == nil {
		t.Fatal("nil context")
	}
}

func TestProductTrustStateD7JournalCapacityFailsClosed(t *testing.T) {
	f := newStateFixture(t)
	s, _ := createFixture(t, f)
	if err := s.db.Update(func(tx *bolt.Tx) error {
		r := s.current
		r.Journal = make([]JournalEntry, MaxOperations)
		for i := range r.Journal {
			r.Journal[i] = JournalEntry{Operation: d7Operation(f, fmt.Sprintf("%032x", i+1), "verify", nil), State: "PREPARED", OutcomeData: map[string]string{}}
		}
		raw, err := encodeRecord(&r)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketName).Put(recordName, raw)
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.db.View(func(tx *bolt.Tx) error { r, _, err := s.read(tx); s.current = r; return err }); err != nil {
		t.Fatal(err)
	}
	if err := s.PrepareOperation(context.Background(), d7Operation(f, strings.Repeat("f", 32), "verify", nil)); !errors.Is(err, ErrCapacity) {
		t.Fatalf("capacity=%v", err)
	}
	if len(d7Entries(t, s)) != MaxOperations {
		t.Fatal("journal silently evicted operations")
	}
}

func TestProductTrustStateD7ProcessCrashKeepsAtomicFacts(t *testing.T) {
	for _, stage := range []string{"intent", "prepared-audit", "reserved", "consumed", "committed", "acked"} {
		t.Run(stage, func(t *testing.T) {
			f := newStateFixture(t)
			s, path := createFixture(t, f)
			doc := f.document
			doc.Generation = 2
			update := f.sign(t, doc)
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestProductTrustStateD7ProcessHelper$")
			cmd.Env = append(os.Environ(), "CHENGWANG_D7_STAGE="+stage, "CHENGWANG_D7_PATH="+path, "CHENGWANG_D7_ANCHOR="+base64.StdEncoding.EncodeToString(marshalFixture(t, f.anchor)), "CHENGWANG_D7_APPROVAL="+base64.StdEncoding.EncodeToString(f.approval), "CHENGWANG_D7_UPDATE="+base64.StdEncoding.EncodeToString(update))
			out, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 83 {
				t.Fatalf("durable boundary child failed: %v %s", err, out)
			}
			r, err := Open(context.Background(), path, f.anchor)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			e := d7Entries(t, r)[0]
			want := "PREPARED"
			switch stage {
			case "reserved":
				want = "RESERVED"
			case "consumed", "acked":
				want = "CONSUMED"
			case "committed":
				want = "COMMITTED"
			}
			if e.State != want {
				t.Fatal("crash exposed mismatched outcome")
			}
			if stage == "acked" && !e.Acknowledged {
				t.Fatal("ack did not survive process exit")
			}
			if stage == "reserved" || stage == "consumed" || stage == "acked" {
				if _, err = r.Begin(context.Background(), "fixture-policy", f.approval); !errors.Is(err, ErrReplay) {
					t.Fatal("crash revived signed grant")
				}
			}
		})
	}
}

func TestProductTrustStateD7ProcessHelper(t *testing.T) {
	stage := os.Getenv("CHENGWANG_D7_STAGE")
	if stage == "" {
		return
	}
	decode := func(name string) []byte {
		raw, err := base64.StdEncoding.DecodeString(os.Getenv(name))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	var f stateFixture
	if json.Unmarshal(decode("CHENGWANG_D7_ANCHOR"), &f.anchor) != nil {
		t.Fatal("child public anchor")
	}
	f.approval = decode("CHENGWANG_D7_APPROVAL")
	s, err := Open(context.Background(), os.Getenv("CHENGWANG_D7_PATH"), f.anchor)
	if err != nil {
		t.Fatal(err)
	}
	kind := "verify"
	raw := decode("CHENGWANG_D7_UPDATE")
	if stage == "committed" {
		kind = "update"
	}
	op := d7Operation(f, strings.Repeat("7", 32), kind, raw)
	if err = s.PrepareOperation(context.Background(), op); err != nil {
		t.Fatal(err)
	}
	if stage == "intent" {
		os.Exit(83)
	}
	if err = s.BindPreparedAudit(context.Background(), op.ID, strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if stage == "prepared-audit" {
		os.Exit(83)
	}
	if stage == "committed" {
		if err = s.UpdateTracked(context.Background(), raw, op.ID); err != nil {
			t.Fatal(err)
		}
		os.Exit(83)
	}
	ticket, err := s.BeginTracked(context.Background(), "fixture-policy", f.approval, op.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if stage == "reserved" {
		os.Exit(83)
	}
	if err = s.Complete(context.Background(), ticket, hash([]byte("durable-evidence"))); err != nil {
		t.Fatal(err)
	}
	if stage == "acked" {
		if err = s.AcknowledgeOperation(context.Background(), op.ID, strings.Repeat("b", 64)); err != nil {
			t.Fatal(err)
		}
	}
	os.Exit(83) // True process exit bypasses Close; it does not simulate power loss.
}
