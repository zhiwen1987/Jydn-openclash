//go:build linux

package main

// These are real runProduct/TLS integration tests in this process. They do
// not execute a Docker image, introduce a product fault hook, or grant recovery
// or deployment authority. The source keeps serving 200; no one-shot fixture
// conceals repeated candidates from the production refresh worker.
import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"chengwang/image-binding/trustcatalog"
	"chengwang/image-binding/truststate"
	"chengwang/internal/evidence"
	"chengwang/internal/imagetrust"
)

type candidateD12RefreshPlan struct {
	latest, firstLatest   []byte
	generations           map[string][]byte
	latestGETs            atomic.Int64
	intermediateGETs      atomic.Int64
	completedLatest       atomic.Int64
	completedIntermediate atomic.Int64
	mu                    sync.Mutex
	paths                 []string
}

type candidateD12RefreshFeed struct {
	server   *httptest.Server
	plan     atomic.Pointer[candidateD12RefreshPlan]
	requests atomic.Int64
	invalid  atomic.Bool
}

func candidateD12RefreshMaterial(t *testing.T) (productD9Fixture, func(uint64, int64) []byte) {
	t.Helper()
	base, _ := candidateD7Fixture(t)
	var original trustcatalog.Envelope
	var document trustcatalog.Document
	if json.Unmarshal(base.catalogue, &original) != nil || json.Unmarshal(original.Payload, &document) != nil {
		t.Fatal("decode isolated signed catalogue template")
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate isolated refresh signing key")
	}
	key := trustcatalog.Key{ID: trustcatalog.KeyID(public), PublicKey: public}
	document.RootKeys = []trustcatalog.Key{key}
	document.NotBeforeUnix, document.NotAfterUnix = time.Now().Unix()-30, time.Now().Unix()+1200
	sign := func(generation uint64, notBefore int64) []byte {
		t.Helper()
		copy := document
		copy.Generation = generation
		if notBefore != 0 {
			copy.NotBeforeUnix = notBefore
		}
		return candidateD7Signed(t, copy, key, private)
	}
	base.catalogue = sign(1, 0)
	base.anchor = trustcatalog.Anchor{StoreID: document.StoreID, InitialSHA256: candidateHash(base.catalogue), Keys: []trustcatalog.Key{key}, Threshold: 1}
	// D7 intentionally does not expose its private signing key. Keep its
	// fixture intact and provision this independent real Store, never Service.
	base.config.StorePath = filepath.Join(filepath.Dir(base.file), "d12-refresh-trust")
	candidatePrivateFile(t, base.config.AnchorFile, candidateJSON(t, base.anchor))
	store, err := truststate.Create(context.Background(), base.config.StorePath, base.anchor, base.catalogue)
	if err != nil {
		t.Fatal("create independent refresh state")
	}
	defer store.Close()
	state, inspectErr := store.Inspect(context.Background())
	if inspectErr != nil || store.Close() != nil || state.Sequence != 1 {
		t.Fatal("close independent initial refresh state")
	}
	base.sequence = state.Sequence
	return productD9FromCandidate(t, base), sign
}

func candidateD12RefreshBadSignature(t *testing.T, raw []byte, bit byte) []byte {
	t.Helper()
	var envelope trustcatalog.Envelope
	if json.Unmarshal(raw, &envelope) != nil || len(envelope.Signatures) != 1 || len(envelope.Signatures[0].Signature) != ed25519.SignatureSize || bit == 0 {
		t.Fatal("invalid isolated signature rejection material")
	}
	envelope.Signatures[0].Signature[0] ^= bit
	bad := candidateJSON(t, envelope)
	if bytes.Equal(raw, bad) {
		t.Fatal("signature rejection material unchanged")
	}
	return bad
}

func candidateD12RefreshSource(t *testing.T, fixture *productD9Fixture, plan *candidateD12RefreshPlan) *candidateD12RefreshFeed {
	t.Helper()
	feed := &candidateD12RefreshFeed{}
	feed.plan.Store(plan)
	feed.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		feed.requests.Add(1)
		if r.TLS == nil || r.Method != http.MethodGet || r.Header.Get("Authorization") != "" || r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("Accept-Encoding") != "" || r.Header.Get("Accept") != "application/json" {
			feed.invalid.Store(true)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		current := feed.plan.Load()
		var body []byte
		latest := false
		if r.URL.RequestURI() == "/feed/latest.json" {
			latest = true
			count := current.latestGETs.Add(1)
			body = current.latest
			if count == 1 && current.firstLatest != nil {
				body = current.firstLatest
			}
		} else if raw, ok := current.generations[r.URL.RequestURI()]; ok {
			current.intermediateGETs.Add(1)
			body = raw
		} else {
			feed.invalid.Store(true)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		current.mu.Lock()
		if len(current.paths) < 256 {
			current.paths = append(current.paths, r.URL.RequestURI())
		} else {
			feed.invalid.Store(true)
		}
		current.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		written, writeErr := w.Write(body)
		// Entry counts select firstLatest; only a complete actual write is
		// evidence of a repeated 200 body. Shutdown write failures are neither
		// completed responses nor protocol-invalid requests.
		if writeErr == nil && written == len(body) {
			if latest {
				current.completedLatest.Add(1)
			} else {
				current.completedIntermediate.Add(1)
			}
		}
	}))
	t.Cleanup(feed.server.Close)
	certificate := feed.server.Certificate()
	c := &fixture.candidate.config
	c.WritesEnabled, c.RefreshEnabled = true, true
	c.RefreshURL, c.RefreshIP = feed.server.URL+"/feed", "127.0.0.1"
	c.RefreshSPKI = candidateHash(certificate.RawSubjectPublicKeyInfo)
	c.RefreshCAFile = filepath.Join(filepath.Dir(fixture.candidate.file), "d12-refresh-ca.pem")
	c.RefreshIntervalSeconds, c.RefreshMaxAgeSeconds, c.RefreshTimeoutSeconds = 1, 3, 2
	candidatePrivateFile(t, c.RefreshCAFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}))
	candidateD7Write(t, fixture.candidate)
	return feed
}

type candidateD12RefreshRuntime struct {
	fixture productD9Fixture
	client  *http.Client
	base    string
	stop    func()
}

func candidateD12RefreshStart(t *testing.T, fixture productD9Fixture) candidateD12RefreshRuntime {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ready, done := make(chan string, 1), make(chan error, 1)
	go func() {
		done <- runProduct(ctx, fixture.candidate.file, fixture.file, func(network, address string) (net.Listener, error) {
			if network != "tcp" || address != fixture.config.Addr {
				return nil, errConfiguration
			}
			listener, err := net.Listen(network, address)
			if err == nil {
				ready <- listener.Addr().String()
			}
			return listener, err
		})
	}()
	stopped := false
	stop := func() {
		t.Helper()
		if stopped {
			return
		}
		cancel()
		select {
		case err := <-done:
			stopped = true
			if err != nil {
				t.Error("real product refresh runtime failed graceful shutdown")
			}
		case <-time.After(12 * time.Second):
			t.Error("real product refresh worker did not join")
		}
	}
	t.Cleanup(stop)
	var address string
	select {
	case address = <-ready:
	case <-done:
		stopped = true
		cancel()
		t.Fatal("real product refresh runtime failed before listener")
	case <-time.After(5 * time.Second):
		t.Fatal("real product refresh runtime listener deadline")
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, ForceAttemptHTTP2: false, TLSClientConfig: &tls.Config{RootCAs: fixture.roots, MinVersion: tls.VersionTLS12}}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return candidateD12RefreshRuntime{fixture: fixture, client: client, base: "https://" + address, stop: stop}
}

func (runtime candidateD12RefreshRuntime) read(t *testing.T, path string, out any) bool {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, runtime.base+path, nil)
	if err != nil {
		t.Fatal("build real TLS refresh status request")
	}
	request.Header.Set("Authorization", "Bearer "+runtime.fixture.candidate.token)
	response, err := runtime.client.Do(request)
	if err != nil {
		t.Fatal("real TLS refresh status request failed")
	}
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || len(raw) > 1<<20 || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
		t.Fatal("real TLS refresh status response rejected")
	}
	// Ordinary read-side sequence fences may race the real outbox writer.
	// Retry only those bounded observations, never a refresh/business call.
	if response.StatusCode == http.StatusConflict || response.StatusCode == http.StatusServiceUnavailable {
		return false
	}
	if response.StatusCode != http.StatusOK {
		t.Fatal("real TLS refresh status HTTP result rejected")
	}
	if bytes.Contains(raw, []byte(runtime.fixture.candidate.token)) || bytes.Contains(raw, []byte(runtime.fixture.candidate.config.RefreshURL)) || bytes.Contains(raw, []byte("PRIVATE KEY")) || json.Unmarshal(raw, out) != nil {
		t.Fatal("refresh status leaked excluded material or invalid DTO")
	}
	return true
}

func (runtime candidateD12RefreshRuntime) snapshot(t *testing.T) (imagetrust.Status, imagetrust.History, bool) {
	t.Helper()
	var status imagetrust.Status
	var history imagetrust.History
	if !runtime.read(t, "/api/v1/image-trust", &status) || !runtime.read(t, "/api/v1/image-trust/history?limit=50", &history) {
		return status, history, false
	}
	if status.Authorization != "BLOCKED" || status.DeviceActionsExecuted || status.StoreID != runtime.fixture.candidate.anchor.StoreID || history.Authorization != "BLOCKED" || history.DeviceActionsExecuted {
		t.Fatal("real refresh advisory boundary changed")
	}
	return status, history, true
}

func (runtime candidateD12RefreshRuntime) wait(t *testing.T, duration time.Duration, condition func(imagetrust.Status, imagetrust.History) bool) (imagetrust.Status, imagetrust.History) {
	t.Helper()
	deadline := time.Now().Add(duration)
	for time.Now().Before(deadline) {
		status, history, observed := runtime.snapshot(t)
		if observed && status.Sequence == history.Sequence && history.Total == len(history.Entries) && condition(status, history) {
			return status, history
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("actual refresh source/runtime observation deadline")
	return imagetrust.Status{}, imagetrust.History{}
}

func candidateD12RefreshHistory(t *testing.T, status imagetrust.Status, history imagetrust.History, generation uint64, catalogue []byte, outcomes ...string) {
	t.Helper()
	if !status.Healthy || !status.Fresh || !status.RefreshRequired || status.Generation != generation || status.CatalogueSHA256 != candidateHash(catalogue) || status.LedgerEntries != 0 || status.Sequence != 1+uint64(4*len(outcomes)) || history.Sequence != status.Sequence || history.Total != len(outcomes) || len(history.Entries) != len(outcomes) {
		t.Fatal("real refresh state or journal tally mismatch")
	}
	wanted := map[string]int{}
	for _, outcome := range outcomes {
		wanted[outcome]++
	}
	for _, entry := range history.Entries {
		if entry.ActorID != "image-trust-refresh" || entry.Kind != "update" || !entry.Acknowledged || len(entry.PreparedAuditHash) != 64 || len(entry.ResultAuditHash) != 64 || wanted[entry.Outcome] == 0 {
			t.Fatal("real refresh audit identity/outcome mismatch")
		}
		wanted[entry.Outcome]--
	}
	for _, count := range wanted {
		if count != 0 {
			t.Fatal("real refresh outcome missing")
		}
	}
}

func candidateD12RefreshStopped(t *testing.T, runtime candidateD12RefreshRuntime, feed *candidateD12RefreshFeed, generation uint64, catalogue []byte, expectedRaws [][]byte, outcomes ...string) {
	t.Helper()
	if len(expectedRaws) != len(outcomes) {
		t.Fatal("ordered refresh candidate evidence incomplete")
	}
	runtime.stop()
	before := feed.requests.Load()
	time.Sleep(60 * time.Millisecond)
	if feed.requests.Load() != before || feed.invalid.Load() {
		t.Fatal("source used unexpected transport or refresh survived joined shutdown")
	}
	f := runtime.fixture.candidate
	store, err := truststate.Open(context.Background(), f.config.StorePath, f.anchor)
	if err != nil {
		t.Fatal("refresh retained the real Store lock")
	}
	defer store.Close()
	state, inspectErr := store.Inspect(context.Background())
	journal, journalErr := store.Journal(context.Background())
	if inspectErr != nil || journalErr != nil || store.Close() != nil || state.Sequence != 1+uint64(4*len(outcomes)) || state.Catalogue.Generation != generation || state.Catalogue.SHA256 != candidateHash(catalogue) || state.LedgerUsed != 0 || len(journal) != len(outcomes) {
		t.Fatal("stopped refresh durable Store changed")
	}
	audit, err := evidence.Open(f.config.AuditDir)
	if err != nil {
		t.Fatal("refresh retained the real audit lock")
	}
	defer audit.Close()
	proof, err := audit.Verify()
	view, viewErr := audit.RecoverySnapshot()
	if err != nil || viewErr != nil || !proof.Valid || proof.Count != uint64(2*len(outcomes)) || proof.Count != proof.ExpectedCount || proof.LastHash != proof.ExpectedLastHash {
		t.Fatal("stopped refresh audit chain mismatch")
	}
	for index, entry := range journal {
		rawHash := candidateHash(expectedRaws[index])
		prepared, foundPrepared := view.Lookup("image-trust/" + entry.Operation.ID + "/prepared")
		result, foundResult := view.Lookup("image-trust/" + entry.Operation.ID + "/result")
		label := "completed"
		if outcomes[index] == truststate.OutcomeRejected {
			label = "rejected"
		}
		if entry.Outcome != outcomes[index] || !entry.Acknowledged || entry.Operation.ActorID != "image-trust-refresh" || !foundPrepared || !foundResult || prepared.ActorID != "image-trust-refresh" || result.ActorID != "image-trust-refresh" || prepared.Hash != entry.Operation.PreparedAuditHash || result.Hash != entry.ResultAuditHash || result.Result != label {
			t.Fatal("durable refresh journal is not bound to actual audit events")
		}
		if entry.Operation.Kind != "update" || len(entry.Operation.Data) != 1 || entry.Operation.Data["catalogueSHA256"] != rawHash || len(prepared.Data) != 1 || prepared.Data["catalogueSHA256"] != rawHash {
			t.Fatal("ordered refresh candidate hash differs from actual operation/prepared evidence")
		}
		if outcomes[index] == truststate.OutcomeCatalogueCommitted {
			if entry.CatalogueSHA256 != rawHash || len(result.Data) != 1 || result.Data["catalogueSHA256"] != rawHash {
				t.Fatal("committed refresh candidate hash differs from actual result evidence")
			}
		} else if outcomes[index] != truststate.OutcomeRejected || entry.CatalogueSHA256 != "" || len(result.Data) != 0 {
			t.Fatal("rejected refresh acquired a committed catalogue fact")
		}
	}
}

func TestCandidateD12RefreshRepeatedSignedRejectionDoesNotRenew(t *testing.T) {
	fixture, sign := candidateD12RefreshMaterial(t)
	bad := candidateD12RefreshBadSignature(t, sign(2, 0), 1)
	warm := &candidateD12RefreshPlan{latest: fixture.candidate.catalogue}
	feed := candidateD12RefreshSource(t, &fixture, warm)
	runtime := candidateD12RefreshStart(t, fixture)
	runtime.wait(t, 5*time.Second, func(s imagetrust.Status, h imagetrust.History) bool {
		return s.RefreshFresh && s.RefreshLastSuccessUnix > 0 && s.RefreshUntilUnix > s.RefreshLastSuccessUnix && h.Total == 0
	})
	plan := &candidateD12RefreshPlan{latest: bad}
	feed.plan.Store(plan)
	// Run is sequential. Once the first bad response has produced its ACK,
	// any older successful no-op has finished. Sample the stable bad-phase
	// confirmation baseline here, not across the legitimate in-flight switch.
	confirmed, firstHistory := runtime.wait(t, 5*time.Second, func(s imagetrust.Status, h imagetrust.History) bool {
		return plan.completedLatest.Load() >= 1 && h.Total == 1 && s.RefreshLastSuccessUnix > 0
	})
	candidateD12RefreshHistory(t, confirmed, firstHistory, 1, fixture.candidate.catalogue, truststate.OutcomeRejected)
	status, history := runtime.wait(t, 9*time.Second, func(s imagetrust.Status, h imagetrust.History) bool {
		return plan.completedLatest.Load() >= 3 && h.Total == 1 && !s.RefreshFresh
	})
	candidateD12RefreshHistory(t, status, history, 1, fixture.candidate.catalogue, truststate.OutcomeRejected)
	if status.RefreshLastSuccessUnix != confirmed.RefreshLastSuccessUnix || status.RefreshUntilUnix != confirmed.RefreshUntilUnix {
		t.Fatal("repeated rejected 200 renewed source freshness")
	}
	candidateD12RefreshStopped(t, runtime, feed, 1, fixture.candidate.catalogue, [][]byte{bad}, truststate.OutcomeRejected)
}

func TestCandidateD12RefreshFutureCandidateBecomesEligible(t *testing.T) {
	fixture, sign := candidateD12RefreshMaterial(t)
	notBefore := time.Now().Add(6 * time.Second).Unix()
	future := sign(2, notBefore)
	plan := &candidateD12RefreshPlan{latest: future}
	feed := candidateD12RefreshSource(t, &fixture, plan)
	runtime := candidateD12RefreshStart(t, fixture)
	status, history := runtime.wait(t, 4*time.Second, func(s imagetrust.Status, h imagetrust.History) bool {
		return plan.completedLatest.Load() >= 3 && h.Total == 1 && !s.RefreshFresh
	})
	candidateD12RefreshHistory(t, status, history, 1, fixture.candidate.catalogue, truststate.OutcomeRejected)
	if time.Now().Unix() >= notBefore || status.RefreshLastSuccessUnix != 0 || status.RefreshUntilUnix != 0 {
		t.Fatal("future candidate did not exercise a real pre-eligibility refusal")
	}
	status, history = runtime.wait(t, 10*time.Second, func(s imagetrust.Status, h imagetrust.History) bool {
		return s.Generation == 2 && s.RefreshFresh && h.Total == 2
	})
	candidateD12RefreshHistory(t, status, history, 2, future, truststate.OutcomeRejected, truststate.OutcomeCatalogueCommitted)
	if plan.completedLatest.Load() < 4 {
		t.Fatal("future candidate installed without a later actual source poll")
	}
	candidateD12RefreshStopped(t, runtime, feed, 2, future, [][]byte{future, future}, truststate.OutcomeRejected, truststate.OutcomeCatalogueCommitted)
}

func TestCandidateD12RefreshSourceBytesChangeRecovers(t *testing.T) {
	fixture, sign := candidateD12RefreshMaterial(t)
	good := sign(2, 0)
	badA, badB := candidateD12RefreshBadSignature(t, good, 1), candidateD12RefreshBadSignature(t, good, 2)
	if bytes.Equal(badA, badB) {
		t.Fatal("distinct rejected source bytes collapsed")
	}
	first := &candidateD12RefreshPlan{latest: badA}
	feed := candidateD12RefreshSource(t, &fixture, first)
	runtime := candidateD12RefreshStart(t, fixture)
	status, history := runtime.wait(t, 5*time.Second, func(s imagetrust.Status, h imagetrust.History) bool {
		return first.completedLatest.Load() >= 3 && h.Total == 1
	})
	candidateD12RefreshHistory(t, status, history, 1, fixture.candidate.catalogue, truststate.OutcomeRejected)
	second := &candidateD12RefreshPlan{latest: badB}
	feed.plan.Store(second)
	status, history = runtime.wait(t, 5*time.Second, func(s imagetrust.Status, h imagetrust.History) bool {
		return second.completedLatest.Load() >= 3 && h.Total == 2
	})
	candidateD12RefreshHistory(t, status, history, 1, fixture.candidate.catalogue, truststate.OutcomeRejected, truststate.OutcomeRejected)
	original := &candidateD12RefreshPlan{latest: badA}
	feed.plan.Store(original)
	status, history = runtime.wait(t, 5*time.Second, func(s imagetrust.Status, h imagetrust.History) bool {
		return original.completedLatest.Load() >= 3 && h.Total == 2
	})
	candidateD12RefreshHistory(t, status, history, 1, fixture.candidate.catalogue, truststate.OutcomeRejected, truststate.OutcomeRejected)
	if status.RefreshFresh || status.RefreshLastSuccessUnix != 0 || status.RefreshUntilUnix != 0 {
		t.Fatal("changed/repeated rejected source became confirmed")
	}
	feed.plan.Store(&candidateD12RefreshPlan{latest: good})
	status, history = runtime.wait(t, 5*time.Second, func(s imagetrust.Status, h imagetrust.History) bool {
		return s.Generation == 2 && s.RefreshFresh && h.Total == 3
	})
	candidateD12RefreshHistory(t, status, history, 2, good, truststate.OutcomeRejected, truststate.OutcomeRejected, truststate.OutcomeCatalogueCommitted)
	candidateD12RefreshStopped(t, runtime, feed, 2, good, [][]byte{badA, badB, good}, truststate.OutcomeRejected, truststate.OutcomeRejected, truststate.OutcomeCatalogueCommitted)
}

func TestCandidateD12RefreshSequentialCatchupAndPartialPrefixRecovers(t *testing.T) {
	fixture, sign := candidateD12RefreshMaterial(t)
	two, three, four, five := sign(2, 0), sign(3, 0), sign(4, 0), sign(5, 0)
	catchup := &candidateD12RefreshPlan{latest: three, generations: map[string][]byte{"/feed/2.json": two}}
	feed := candidateD12RefreshSource(t, &fixture, catchup)
	runtime := candidateD12RefreshStart(t, fixture)
	status, history := runtime.wait(t, 5*time.Second, func(s imagetrust.Status, h imagetrust.History) bool {
		return s.Generation == 3 && s.RefreshFresh && h.Total == 2
	})
	candidateD12RefreshHistory(t, status, history, 3, three, truststate.OutcomeCatalogueCommitted, truststate.OutcomeCatalogueCommitted)
	catchup.mu.Lock()
	order := append([]string(nil), catchup.paths...)
	catchup.mu.Unlock()
	if len(order) < 2 || order[0] != "/feed/latest.json" || order[1] != "/feed/2.json" || catchup.completedIntermediate.Load() != 1 {
		t.Fatal("actual source catchup did not fetch the sequential intermediate")
	}
	partial := &candidateD12RefreshPlan{latest: candidateD12RefreshBadSignature(t, five, 1), generations: map[string][]byte{"/feed/4.json": four}}
	feed.plan.Store(partial)
	status, history = runtime.wait(t, 6*time.Second, func(s imagetrust.Status, h imagetrust.History) bool {
		return partial.completedLatest.Load() >= 3 && s.Generation == 4 && !s.RefreshFresh && h.Total == 4
	})
	candidateD12RefreshHistory(t, status, history, 4, four, truststate.OutcomeCatalogueCommitted, truststate.OutcomeCatalogueCommitted, truststate.OutcomeCatalogueCommitted, truststate.OutcomeRejected)
	partial.mu.Lock()
	order = append([]string(nil), partial.paths...)
	partial.mu.Unlock()
	if len(order) < 2 || order[0] != "/feed/latest.json" || order[1] != "/feed/4.json" || partial.completedIntermediate.Load() != 1 {
		t.Fatal("partial catchup retried or rolled back its committed prefix")
	}
	feed.plan.Store(&candidateD12RefreshPlan{latest: five})
	status, history = runtime.wait(t, 5*time.Second, func(s imagetrust.Status, h imagetrust.History) bool {
		return s.Generation == 5 && s.RefreshFresh && h.Total == 5
	})
	candidateD12RefreshHistory(t, status, history, 5, five, truststate.OutcomeCatalogueCommitted, truststate.OutcomeCatalogueCommitted, truststate.OutcomeCatalogueCommitted, truststate.OutcomeRejected, truststate.OutcomeCatalogueCommitted)
	candidateD12RefreshStopped(t, runtime, feed, 5, five, [][]byte{two, three, four, partial.latest, five}, truststate.OutcomeCatalogueCommitted, truststate.OutcomeCatalogueCommitted, truststate.OutcomeCatalogueCommitted, truststate.OutcomeRejected, truststate.OutcomeCatalogueCommitted)
}
