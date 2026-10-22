//go:build linux

package truststate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func previewRecordD12(t *testing.T, s *Store) []byte {
	t.Helper()
	var raw []byte
	if err := s.db.View(func(tx *bolt.Tx) error {
		raw = bytes.Clone(tx.Bucket(bucketName).Get(recordName))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestProductTrustStateD12PreviewValidReadOnly(t *testing.T) {
	f := newStateFixture(t)
	s, _ := createFixture(t, f)
	doc := f.document
	doc.Generation = 2
	raw := f.sign(t, doc)
	before := previewRecordD12(t, s)
	for i := 0; i < 5; i++ {
		p, err := s.PreviewUpdate(context.Background(), raw)
		if err != nil || !p.Eligible || p.BaseGeneration != 1 || p.BaseSHA256 != hash(f.initial) {
			t.Fatal("valid advisory preview missing", err)
		}
	}
	if !bytes.Equal(before, previewRecordD12(t, s)) {
		t.Fatal("preview changed durable record")
	}
	if err := s.Update(context.Background(), raw); err != nil {
		t.Fatal("preview prevented real transactional validation", err)
	}
}

func TestProductTrustStateD12PreviewInvalidReadOnly(t *testing.T) {
	f := newStateFixture(t)
	s, _ := createFixture(t, f)
	doc := f.document
	doc.Generation = 2
	valid := f.sign(t, doc)
	var envelope map[string]any
	if json.Unmarshal(valid, &envelope) != nil {
		t.Fatal("decode inert test envelope")
	}
	signatures := envelope["signatures"].([]any)
	signatures[0].(map[string]any)["signature"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
	badSignature := marshalFixture(t, envelope)
	before := previewRecordD12(t, s)
	for _, raw := range [][]byte{[]byte("{}"), badSignature, f.initial} {
		p, err := s.PreviewUpdate(context.Background(), raw)
		if err != nil || p.Eligible || p.BaseGeneration != 1 || p.BaseSHA256 != hash(f.initial) {
			t.Fatal("invalid candidate preview must be healthy but ineligible", err)
		}
	}
	if !bytes.Equal(before, previewRecordD12(t, s)) {
		t.Fatal("invalid previews wrote the database")
	}
	// Deliberate corruption of this test-only database must not be reported as
	// an ordinary rejected candidate, nor repaired by an advisory read.
	if err := s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketName).Put(recordName, []byte("{}"))
	}); err != nil {
		t.Fatal(err)
	}
	damaged := previewRecordD12(t, s)
	if p, err := s.PreviewUpdate(context.Background(), valid); !errors.Is(err, ErrPoisoned) || p != (UpdatePreview{}) || !bytes.Equal(damaged, previewRecordD12(t, s)) {
		t.Fatal("corrupt record hidden as candidate rejection or repaired", err)
	}
}

func TestProductTrustStateD12PreviewRechecksTimeWindow(t *testing.T) {
	f := newStateFixture(t)
	s, _ := createFixture(t, f)
	doc := f.document
	doc.Generation = 2
	doc.NotBeforeUnix = time.Now().Unix() + 20
	raw := f.sign(t, doc)
	before := previewRecordD12(t, s)
	// Private test clock only; production and Windows clocks are not changed.
	s.clock = func() time.Time { return time.Unix(doc.NotBeforeUnix-1, 0) }
	p, err := s.PreviewUpdate(context.Background(), raw)
	if err != nil || p.Eligible {
		t.Fatal("future candidate accepted too soon", err)
	}
	s.clock = func() time.Time { return time.Unix(doc.NotBeforeUnix, 0) }
	p, err = s.PreviewUpdate(context.Background(), raw)
	if err != nil || !p.Eligible {
		t.Fatal("same original bytes not rechecked at NotBefore", err)
	}
	s.clock = func() time.Time { return time.Unix(doc.NotAfterUnix, 0) }
	p, err = s.PreviewUpdate(context.Background(), raw)
	if err != nil || p.Eligible || !bytes.Equal(before, previewRecordD12(t, s)) {
		t.Fatal("expired candidate preview or durable time altered", err)
	}
}

func TestProductTrustStateD12PreviewTracksCurrentBase(t *testing.T) {
	f := newStateFixture(t)
	s, _ := createFixture(t, f)
	doc := f.document
	doc.Generation = 2
	raw2 := f.sign(t, doc)
	doc.Generation = 3
	raw3 := f.sign(t, doc)
	p, err := s.PreviewUpdate(context.Background(), raw3)
	if err != nil || p.Eligible || p.BaseGeneration != 1 {
		t.Fatal("skipped generation preview accepted", err)
	}
	if err = s.Update(context.Background(), raw2); err != nil {
		t.Fatal(err)
	}
	before := previewRecordD12(t, s)
	p, err = s.PreviewUpdate(context.Background(), raw3)
	if err != nil || !p.Eligible || p.BaseGeneration != 2 || p.BaseSHA256 != hash(raw2) || !bytes.Equal(before, previewRecordD12(t, s)) {
		t.Fatal("preview did not bind current catalogue", err)
	}
}

func TestProductTrustStateD12PreviewRejectsInvalidContextsAndClosed(t *testing.T) {
	f := newStateFixture(t)
	s, _ := createFixture(t, f)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	before := previewRecordD12(t, s)
	for _, attemptContext := range []context.Context{nil, ctx} {
		if p, err := s.PreviewUpdate(attemptContext, f.initial); err == nil || p != (UpdatePreview{}) {
			t.Fatal("invalid context got usable preview")
		}
	}
	for _, raw := range [][]byte{nil, {}, make([]byte, (256<<10)+1)} {
		if p, err := s.PreviewUpdate(context.Background(), raw); err == nil || p != (UpdatePreview{}) {
			t.Fatal("invalid size got usable preview")
		}
	}
	if !bytes.Equal(before, previewRecordD12(t, s)) {
		t.Fatal("invalid call changed record")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if p, err := s.PreviewUpdate(context.Background(), f.initial); !errors.Is(err, ErrClosed) || p != (UpdatePreview{}) {
		t.Fatal("closed store got usable preview")
	}
	var zero *Store
	if p, err := zero.PreviewUpdate(context.Background(), f.initial); err == nil || p != (UpdatePreview{}) {
		t.Fatal("nil store got usable preview")
	}
}

func TestProductTrustStateD12PreviewFailsClosedOnClockRegression(t *testing.T) {
	f := newStateFixture(t)
	s, _ := createFixture(t, f)
	before := previewRecordD12(t, s)
	s.clock = func() time.Time { return time.Unix(0, s.current.LastWallUnixNano-1) }
	if p, err := s.PreviewUpdate(context.Background(), f.initial); !errors.Is(err, ErrPoisoned) || p != (UpdatePreview{}) {
		t.Fatal("clock regression disguised as candidate rejection", err)
	}
	if !bytes.Equal(before, previewRecordD12(t, s)) || !s.poisoned {
		t.Fatal("clock failure wrote state or was not fail closed")
	}
}

func TestProductTrustStateD12PreviewPreservesConsumedGrants(t *testing.T) {
	f := newStateFixture(t)
	s, _ := createFixture(t, f)
	ticket := beginFixture(t, s, f)
	// An explicit unit-only ledger marker, not an SDK verification receipt.
	if err := s.Complete(context.Background(), ticket, hash([]byte("D12 preview unit-only ledger marker"))); err != nil {
		t.Fatal(err)
	}
	before := previewRecordD12(t, s)
	doc := f.document
	doc.Generation = 2
	if p, err := s.PreviewUpdate(context.Background(), f.sign(t, doc)); err != nil || !p.Eligible {
		t.Fatal("consumed ledger invalidated independent preview", err)
	}
	if !bytes.Equal(before, previewRecordD12(t, s)) {
		t.Fatal("preview altered burned ledger")
	}
	if _, err := s.Begin(context.Background(), "fixture-policy", f.approval); !errors.Is(err, ErrReplay) {
		t.Fatal("preview unburned grant", err)
	}
}

func TestProductTrustStateD12PreviewDetachedProjectionHasNoAuthority(t *testing.T) {
	f := newStateFixture(t)
	s, _ := createFixture(t, f)
	p, err := s.PreviewUpdate(context.Background(), []byte("{}"))
	if err != nil || p.Eligible {
		t.Fatal("invalid baseline preview", err)
	}
	raw := marshalFixture(t, p)
	for _, secret := range [][]byte{[]byte("payload"), []byte("signature"), []byte("publicKey"), []byte("token"), []byte("history")} {
		if bytes.Contains(raw, secret) {
			t.Fatal("advisory preview exposed private state")
		}
	}
	p.Eligible = true
	p.BaseGeneration = 999
	p.BaseSHA256 = hash([]byte("forged"))
	if err := s.Update(context.Background(), []byte("{}")); !errors.Is(err, ErrInvalid) {
		t.Fatal("mutated projection authorized a catalogue", err)
	}
	state, err := s.Inspect(context.Background())
	if err != nil || state.Sequence != 1 || state.LedgerUsed != 0 || state.Catalogue.Generation != 1 {
		t.Fatal("projection import/mutation changed actual store", err)
	}
}
