//go:build linux

package truststate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"chengwang/image-binding/trustcatalog"
	bolt "go.etcd.io/bbolt"
)

type stateFixture struct {
	anchor            trustcatalog.Anchor
	document          trustcatalog.Document
	initial, approval []byte
	rootPrivate       ed25519.PrivateKey
}

func newStateFixture(t *testing.T) stateFixture {
	t.Helper()
	rootPub, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	approverPub, approverPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	rootKey := trustcatalog.Key{ID: trustcatalog.KeyID(rootPub), PublicKey: rootPub}
	approverKey := trustcatalog.Key{ID: trustcatalog.KeyID(approverPub), PublicKey: approverPub}
	manifest := hash([]byte("inert-image-manifest"))
	payload := marshalFixture(t, map[string]any{
		"schema": "chengwang.image-approval/v1", "policyID": "fixture-policy", "revision": uint64(1), "approverKeyID": approverKey.ID, "notBeforeUnix": now - 60, "notAfterUnix": now + 1800,
		"reference": "registry.fixture.invalid/team/image@" + manifest, "os": "linux", "architecture": "amd64", "variant": "", "registryIPs": []string{"127.0.0.1"}, "registrySPKISHA256": hash([]byte("registry-key")),
		"signature": map[string]any{"artifactSHA256": manifest, "trustedRootSHA256": hash([]byte("fixture-root")), "logID": fmt.Sprintf("%064x", 1), "issuer": "https://issuer.fixture.invalid", "san": "builder@fixture.invalid", "kind": "message-signature"},
	})
	approval := marshalFixture(t, map[string]any{"payload": payload, "signature": ed25519.Sign(approverPrivate, append([]byte("chengwang.image-approval/v1\x00"), payload...))})
	grant := trustcatalog.Grant{ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", PolicyID: "fixture-policy", ApprovalSHA256: hash(payload), ApproverKeyID: approverKey.ID, ManifestSHA256: manifest, Revision: 1}
	doc := trustcatalog.Document{Schema: trustcatalog.Schema, StoreID: "11111111111111111111111111111111", Generation: 1, NotBeforeUnix: now - 60, NotAfterUnix: now + 3600, RootKeys: []trustcatalog.Key{rootKey}, Threshold: 1, Approvers: []trustcatalog.Key{approverKey}, Grants: []trustcatalog.Grant{grant}, PolicyFloors: map[string]uint64{"fixture-policy": 1}, RevokedKeys: []string{}, RevokedApprovals: []string{}, RevokedManifests: []string{}}
	f := stateFixture{document: doc, approval: approval, rootPrivate: rootPrivate}
	f.initial = f.sign(t, doc)
	f.anchor = trustcatalog.Anchor{StoreID: doc.StoreID, InitialSHA256: hash(f.initial), Keys: []trustcatalog.Key{rootKey}, Threshold: 1}
	return f
}
func (f stateFixture) sign(t *testing.T, doc trustcatalog.Document) []byte {
	t.Helper()
	payload := marshalFixture(t, doc)
	return marshalFixture(t, trustcatalog.Envelope{Payload: payload, Signatures: []trustcatalog.Signature{{KeyID: trustcatalog.KeyID(f.rootPrivate.Public().(ed25519.PublicKey)), Signature: ed25519.Sign(f.rootPrivate, append([]byte(trustcatalog.Schema+"\x00"), payload...))}}})
}
func marshalFixture(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func fixturePath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "trust")
}
func createFixture(t *testing.T, f stateFixture) (*Store, string) {
	t.Helper()
	path := fixturePath(t)
	s, err := Create(context.Background(), path, f.anchor, f.initial)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, path
}
func beginFixture(t *testing.T, s *Store, f stateFixture) Ticket {
	t.Helper()
	ticket, err := s.Begin(context.Background(), "fixture-policy", f.approval)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	return ticket
}

func TestTrustStateCreateReserveConsumeReopen(t *testing.T) {
	f := newStateFixture(t)
	s, path := createFixture(t, f)
	if _, err := Create(context.Background(), path, f.anchor, f.initial); err == nil {
		t.Fatal("Create overwrote existing directory")
	}
	ticket := beginFixture(t, s, f)
	if ticket.GrantID() != f.document.Grants[0].ID || ticket.ManifestSHA256() != f.document.Grants[0].ManifestSHA256 || ticket.Generation() != 1 || ticket.CatalogueSHA256() != hash(f.initial) {
		t.Fatal("ticket binding mismatch")
	}
	trust := ticket.Trust()
	trust.PublicKey[0] ^= 255
	if bytes.Equal(trust.PublicKey, ticket.Trust().PublicKey) {
		t.Fatal("Trust returned mutable shared key")
	}
	if err := s.Complete(context.Background(), ticket, hash([]byte("evidence"))); err != nil {
		t.Fatal(err)
	}
	if err := s.Complete(context.Background(), ticket, hash([]byte("evidence"))); !errors.Is(err, ErrReplay) {
		t.Fatalf("second Complete: %v", err)
	}
	if _, err := s.Begin(context.Background(), "fixture-policy", f.approval); !errors.Is(err, ErrReplay) {
		t.Fatalf("same signed grant replay: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(context.Background(), path, f.anchor)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err = reopened.Begin(context.Background(), "fixture-policy", f.approval); !errors.Is(err, ErrReplay) {
		t.Fatalf("reopen replay: %v", err)
	}
	if err = reopened.Complete(context.Background(), ticket, hash([]byte("evidence"))); err == nil {
		t.Fatal("old owner ticket acquired authority after reopen")
	}
	for _, name := range []string{databaseName, markerName} {
		st, err := os.Stat(filepath.Join(path, name))
		if err != nil || st.Mode().Perm() != 0600 {
			t.Fatalf("%s mode/stat: %v", name, err)
		}
	}
}

func TestTrustStateConcurrentSingleWinner(t *testing.T) {
	f := newStateFixture(t)
	s, _ := createFixture(t, f)
	var winners atomic.Int32
	var winner Ticket
	var winnerMu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ticket, err := s.Begin(context.Background(), "fixture-policy", f.approval)
			if err == nil {
				winners.Add(1)
				winnerMu.Lock()
				winner = ticket
				winnerMu.Unlock()
			} else if !errors.Is(err, ErrReplay) {
				t.Errorf("Begin: %v", err)
			}
		}()
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("Begin winners=%d", winners.Load())
	}
	winners.Store(0)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := s.Complete(context.Background(), winner, hash([]byte("evidence")))
			if err == nil {
				winners.Add(1)
			} else if !errors.Is(err, ErrReplay) {
				t.Errorf("Complete: %v", err)
			}
		}()
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("Complete winners=%d", winners.Load())
	}
}

func TestTrustStateUpdateRevokesInFlightGrant(t *testing.T) {
	for _, kind := range []string{"key", "approval", "manifest", "new-generation"} {
		t.Run(kind, func(t *testing.T) {
			f := newStateFixture(t)
			s, path := createFixture(t, f)
			ticket := beginFixture(t, s, f)
			doc := f.document
			doc.Generation = 2
			if kind != "new-generation" {
				doc.Grants = []trustcatalog.Grant{}
			}
			switch kind {
			case "key":
				doc.RevokedKeys = []string{f.document.Grants[0].ApproverKeyID}
				doc.Approvers = []trustcatalog.Key{}
			case "approval":
				doc.RevokedApprovals = []string{f.document.Grants[0].ApprovalSHA256}
			case "manifest":
				doc.RevokedManifests = []string{f.document.Grants[0].ManifestSHA256}
			}
			if err := s.Update(context.Background(), f.sign(t, doc)); err != nil {
				t.Fatal(err)
			}
			if err := s.Complete(context.Background(), ticket, hash([]byte("evidence"))); err == nil {
				t.Fatal("old in-flight ticket completed after update")
			}
			if err := s.Update(context.Background(), f.initial); err == nil {
				t.Fatal("catalogue downgrade accepted")
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			r, err := Open(context.Background(), path, f.anchor)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			if _, err = r.Begin(context.Background(), "fixture-policy", f.approval); err == nil {
				t.Fatal("revoked or reserved grant revived after restart")
			}
		})
	}
}

func TestTrustStateExpiryAndClockRollback(t *testing.T) {
	for _, kind := range []string{"approval-expiry", "catalogue-expiry", "clock-rollback", "expired-catalogue-refresh"} {
		t.Run(kind, func(t *testing.T) {
			f := newStateFixture(t)
			s, _ := createFixture(t, f)
			ticket := beginFixture(t, s, f)
			base := time.Now()
			switch kind {
			case "approval-expiry":
				s.clock = func() time.Time { return time.Unix(ticket.approvalNotAfterUnix, 0) }
			case "catalogue-expiry", "expired-catalogue-refresh":
				s.clock = func() time.Time { return time.Unix(f.document.NotAfterUnix, 0) }
			case "clock-rollback":
				s.clock = func() time.Time { return base.Add(-time.Hour) }
			}
			if kind == "expired-catalogue-refresh" {
				doc := f.document
				doc.Generation = 2
				doc.NotBeforeUnix = f.document.NotAfterUnix - 1
				doc.NotAfterUnix = doc.NotBeforeUnix + 3600
				doc.Grants = []trustcatalog.Grant{}
				if err := s.Update(context.Background(), f.sign(t, doc)); err != nil {
					t.Fatalf("refresh of expired authenticated metadata: %v", err)
				}
				return
			}
			if err := s.Complete(context.Background(), ticket, hash([]byte("evidence"))); err == nil {
				t.Fatal("expired/backward-clock Complete succeeded")
			}
			if kind == "clock-rollback" {
				s.clock = time.Now
				if _, err := s.Begin(context.Background(), "fixture-policy", f.approval); !errors.Is(err, ErrPoisoned) {
					t.Fatalf("clock failure not sticky: %v", err)
				}
			}
		})
	}
}

func TestTrustStateFinalExpiryBurnsConsumedGrant(t *testing.T) {
	for _, kind := range []string{"approval", "catalogue", "clock-rollback"} {
		t.Run(kind, func(t *testing.T) {
			f := newStateFixture(t)
			if kind == "catalogue" {
				// Catalogue expires first in this case, so the two expiry gates are
				// independently exercised rather than both failing at the same time.
				f.document.NotAfterUnix = time.Now().Unix() + 900
				f.initial = f.sign(t, f.document)
				f.anchor.InitialSHA256 = hash(f.initial)
			}
			s, path := createFixture(t, f)
			ticket := beginFixture(t, s, f)
			finalTime := time.Unix(ticket.approvalNotAfterUnix, 0)
			if kind == "catalogue" {
				finalTime = time.Unix(f.document.NotAfterUnix, 0)
			}
			if kind == "clock-rollback" {
				finalTime = time.Now().Add(-time.Hour)
			}
			s.fault = func(stage string) error {
				if stage == "after-commit" {
					s.clock = func() time.Time { return finalTime }
				}
				return nil
			}
			err := s.Complete(context.Background(), ticket, hash([]byte("evidence")))
			want := ErrInvalid
			if kind == "clock-rollback" {
				want = ErrPoisoned
			}
			if !errors.Is(err, want) {
				t.Fatalf("Complete crossed final %s boundary but returned %v", kind, err)
			}
			if len(s.current.Ledger) != 1 || s.current.Ledger[0].Status != "CONSUMED" {
				t.Fatal("post-commit failure undid consumed grant")
			}
			if err = s.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := Open(context.Background(), path, f.anchor)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			if len(reopened.current.Ledger) != 1 || reopened.current.Ledger[0].Status != "CONSUMED" {
				t.Fatal("consumption did not survive restart")
			}
			if _, err = reopened.Begin(context.Background(), "fixture-policy", f.approval); !errors.Is(err, ErrReplay) {
				t.Fatalf("final expiry failure revived grant after reopen: %v", err)
			}
		})
	}
}

func TestTrustStateSafeOpenRejectsMissingTruncatedAndLinks(t *testing.T) {
	for _, kind := range []string{"missing-dir", "missing-db", "empty-db", "truncated-db", "missing-marker", "bad-marker", "db-symlink", "db-hardlink", "db-mode", "directory-symlink", "wrong-anchor"} {
		t.Run(kind, func(t *testing.T) {
			f := newStateFixture(t)
			s, path := createFixture(t, f)
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			dbpath := filepath.Join(path, databaseName)
			markerpath := filepath.Join(path, markerName)
			var err error
			switch kind {
			case "missing-dir":
				path = filepath.Join(filepath.Dir(path), "missing")
			case "missing-db":
				err = os.Remove(dbpath)
			case "empty-db":
				err = os.Truncate(dbpath, 0)
			case "truncated-db":
				err = os.Truncate(dbpath, 100)
			case "missing-marker":
				err = os.Remove(markerpath)
			case "bad-marker":
				err = os.WriteFile(markerpath, []byte("{}"), 0600)
			case "db-symlink":
				err = os.Rename(dbpath, dbpath+".original")
				if err == nil {
					err = os.Symlink(dbpath+".original", dbpath)
				}
			case "db-hardlink":
				err = os.Link(dbpath, dbpath+".other")
			case "db-mode":
				err = os.Chmod(dbpath, 0644)
			case "directory-symlink":
				original := path + ".original"
				err = os.Rename(path, original)
				if err == nil {
					err = os.Symlink(original, path)
				}
			case "wrong-anchor":
				f.anchor.StoreID = "22222222222222222222222222222222"
			}
			if err != nil {
				t.Fatal(err)
			}
			r, err := Open(context.Background(), path, f.anchor)
			if err == nil {
				r.Close()
				t.Fatal("unsafe or missing state reopened")
			}
			if kind == "empty-db" || kind == "truncated-db" {
				st, e := os.Stat(dbpath)
				want := int64(0)
				if kind == "truncated-db" {
					want = 100
				}
				if e != nil || st.Size() != want {
					t.Fatal("Open initialized/truncated existing database")
				}
			}
		})
	}
}

func TestTrustStateLiveIdentityChangePoisons(t *testing.T) {
	for _, kind := range []string{"directory", "database", "marker", "mode", "database-hardlink"} {
		t.Run(kind, func(t *testing.T) {
			f := newStateFixture(t)
			s, path := createFixture(t, f)
			var err error
			switch kind {
			case "directory":
				err = os.Rename(path, path+".old")
				if err == nil {
					err = os.Mkdir(path, 0700)
				}
			case "database":
				name := filepath.Join(path, databaseName)
				err = os.Rename(name, name+".old")
				if err == nil {
					err = os.WriteFile(name, make([]byte, 16384), 0600)
				}
			case "marker":
				name := filepath.Join(path, markerName)
				err = os.Rename(name, name+".old")
				if err == nil {
					err = os.WriteFile(name, s.platform.marker, 0600)
				}
			case "mode":
				err = os.Chmod(path, 0755)
			case "database-hardlink":
				err = os.Link(filepath.Join(path, databaseName), filepath.Join(path, "db-link"))
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.Begin(context.Background(), "fixture-policy", f.approval); !errors.Is(err, ErrPoisoned) {
				t.Fatalf("identity changed: %v", err)
			}
			if _, err = s.Begin(context.Background(), "fixture-policy", f.approval); !errors.Is(err, ErrPoisoned) {
				t.Fatalf("identity failure was not sticky: %v", err)
			}
		})
	}
}

func TestTrustStateTransactionFaultsFailClosed(t *testing.T) {
	for _, stage := range []string{"before-put", "before-commit", "after-commit"} {
		t.Run(stage, func(t *testing.T) {
			f := newStateFixture(t)
			s, path := createFixture(t, f)
			s.fault = func(at string) error {
				if at == stage {
					return errors.New("injected transaction boundary failure")
				}
				return nil
			}
			if ticket, err := s.Begin(context.Background(), "fixture-policy", f.approval); !errors.Is(err, ErrPoisoned) || ticket.owner != nil {
				t.Fatalf("fault returned ticket or success: %v", err)
			}
			s.fault = nil
			if _, err := s.Begin(context.Background(), "fixture-policy", f.approval); !errors.Is(err, ErrPoisoned) {
				t.Fatalf("fault not sticky: %v", err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			r, err := Open(context.Background(), path, f.anchor)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			_, err = r.Begin(context.Background(), "fixture-policy", f.approval)
			if stage == "after-commit" && !errors.Is(err, ErrReplay) {
				t.Fatalf("committed reservation was not burned: %v", err)
			}
			if stage != "after-commit" && err != nil {
				t.Fatalf("rolled back transaction was not old complete state: %v", err)
			}
		})
	}
}

func TestTrustStateLedgerCapacityNeverEvicts(t *testing.T) {
	f := newStateFixture(t)
	s, _ := createFixture(t, f)
	err := s.db.Update(func(tx *bolt.Tx) error {
		r := s.current
		g := f.document.Grants[0]
		r.Ledger = make([]ledgerEntry, maxLedgerEntries)
		for i := range r.Ledger {
			r.Ledger[i] = ledgerEntry{GrantID: fmt.Sprintf("%032x", i+1), PolicyID: g.PolicyID, ApprovalSHA256: g.ApprovalSHA256, ManifestSHA256: g.ManifestSHA256, Generation: 1, CatalogueSHA256: hash(f.initial), TokenSHA256: hash([]byte(fmt.Sprint(i))), ApprovalNotAfterUnix: time.Now().Add(time.Hour).Unix(), Status: "CONSUMED", EvidenceSHA256: hash([]byte("evidence"))}
		}
		raw, err := encodeRecord(&r)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketName).Put(recordName, raw)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.db.View(func(tx *bolt.Tx) error { r, _, err := s.read(tx); s.current = r; return err }); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Begin(context.Background(), "fixture-policy", f.approval); !errors.Is(err, ErrCapacity) {
		t.Fatalf("full ledger: %v", err)
	}
	if len(s.current.Ledger) != maxLedgerEntries {
		t.Fatal("ledger evicted receipts")
	}
}

func TestTrustStateRecordChecksumRejectsParseableMutation(t *testing.T) {
	f := newStateFixture(t)
	s, path := createFixture(t, f)
	if err := s.db.Update(func(tx *bolt.Tx) error {
		r := s.current
		r.Sequence++
		return tx.Bucket(bucketName).Put(recordName, marshalFixture(t, r))
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if reopened, err := Open(context.Background(), path, f.anchor); err == nil {
		reopened.Close()
		t.Fatal("parseable changed record bypassed public checksum")
	}
}

func TestTrustStateTicketsAndInvalidInputsHaveNoAuthority(t *testing.T) {
	f := newStateFixture(t)
	s, _ := createFixture(t, f)
	if raw := marshalFixture(t, Ticket{}); string(raw) != "{}" {
		t.Fatal("ticket serialized authority")
	}
	var imported Ticket
	if err := json.Unmarshal([]byte(`{"GrantID":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`), &imported); err != nil {
		t.Fatal(err)
	}
	if s.Complete(context.Background(), imported, hash([]byte("evidence"))) == nil {
		t.Fatal("JSON receipt acquired authority")
	}
	for _, raw := range [][]byte{nil, []byte("{}"), append(bytes.Clone(f.approval), 'x')} {
		if _, err := s.Begin(context.Background(), "fixture-policy", raw); err == nil {
			t.Fatal("invalid approval reserved grant")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Begin(ctx, "fixture-policy", f.approval); err == nil {
		t.Fatal("canceled Begin succeeded")
	}
	if _, err := s.Begin(nil, "fixture-policy", f.approval); err == nil {
		t.Fatal("nil context succeeded")
	}
	if _, err := s.Begin(context.Background(), "other-policy", f.approval); err == nil {
		t.Fatal("unapproved policy succeeded")
	}
	if ticket := beginFixture(t, s, f); s.Complete(nil, ticket, hash([]byte("evidence"))) == nil {
		t.Fatal("nil Complete context succeeded")
	}
}

func TestTrustStateAnchorIsCopied(t *testing.T) {
	f := newStateFixture(t)
	original := cloneAnchor(f.anchor)
	s, path := createFixture(t, f)
	f.anchor.Keys[0].PublicKey[0] ^= 255
	_ = beginFixture(t, s, f)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	r, err := Open(context.Background(), path, original)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
}

func TestTrustStateProcessLockAndCrashDurability(t *testing.T) {
	for _, mode := range []string{"locked", "reserve-crash", "consume-crash"} {
		t.Run(mode, func(t *testing.T) {
			f := newStateFixture(t)
			s, path := createFixture(t, f)
			if mode != "locked" {
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestTrustStateProcessHelper$")
			cmd.Env = append(os.Environ(), "CHENGWANG_TRUSTSTATE_HELPER="+mode, "CHENGWANG_TRUSTSTATE_PATH="+path, "CHENGWANG_TRUSTSTATE_ANCHOR="+base64.StdEncoding.EncodeToString(marshalFixture(t, f.anchor)), "CHENGWANG_TRUSTSTATE_APPROVAL="+base64.StdEncoding.EncodeToString(f.approval))
			output, err := cmd.CombinedOutput()
			if mode == "locked" {
				if err != nil {
					t.Fatalf("second writer was not excluded: %v %s", err, output)
				}
				return
			}
			var exit *exec.ExitError
			want := 73
			if mode == "consume-crash" {
				want = 74
			}
			if !errors.As(err, &exit) || exit.ExitCode() != want {
				t.Fatalf("child did not crash at expected durable boundary: %v %s", err, output)
			}
			r, err := Open(context.Background(), path, f.anchor)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			if _, err = r.Begin(context.Background(), "fixture-policy", f.approval); !errors.Is(err, ErrReplay) {
				t.Fatalf("crashed process revived used grant: %v", err)
			}
			wantStatus := "RESERVED"
			if mode == "consume-crash" {
				wantStatus = "CONSUMED"
			}
			if len(r.current.Ledger) != 1 || r.current.Ledger[0].Status != wantStatus {
				t.Fatal("crash state mismatch")
			}
		})
	}
}

func TestTrustStateProcessHelper(t *testing.T) {
	mode := os.Getenv("CHENGWANG_TRUSTSTATE_HELPER")
	if mode == "" {
		return
	}
	anchorRaw, err := base64.StdEncoding.DecodeString(os.Getenv("CHENGWANG_TRUSTSTATE_ANCHOR"))
	if err != nil {
		t.Fatal(err)
	}
	var anchor trustcatalog.Anchor
	if json.Unmarshal(anchorRaw, &anchor) != nil {
		t.Fatal("bad child anchor")
	}
	s, err := Open(context.Background(), os.Getenv("CHENGWANG_TRUSTSTATE_PATH"), anchor)
	if mode == "locked" {
		if !errors.Is(err, ErrBusy) {
			if s != nil {
				s.Close()
			}
			t.Fatalf("expected writer exclusion, got %v", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	approval, err := base64.StdEncoding.DecodeString(os.Getenv("CHENGWANG_TRUSTSTATE_APPROVAL"))
	if err != nil {
		t.Fatal(err)
	}
	ticket, err := s.Begin(context.Background(), "fixture-policy", approval)
	if err != nil {
		t.Fatal(err)
	}
	if mode == "reserve-crash" {
		os.Exit(73)
	}
	if mode != "consume-crash" {
		t.Fatal("unknown child mode")
	}
	if err = s.Complete(context.Background(), ticket, hash([]byte("evidence"))); err != nil {
		t.Fatal(err)
	}
	os.Exit(74) // Deliberately bypass Close: process crash, not simulated power loss.
}
