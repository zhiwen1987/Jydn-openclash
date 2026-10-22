//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"chengwang/image-binding/trustcatalog"
	"chengwang/image-binding/truststate"
	"chengwang/internal/authz"
	"chengwang/internal/evidence"
	"chengwang/internal/imagetrust"
)

func candidateD7Signed(t *testing.T, document trustcatalog.Document, key trustcatalog.Key, private ed25519.PrivateKey) []byte {
	t.Helper()
	payload := candidateJSON(t, document)
	return candidateJSON(t, trustcatalog.Envelope{Payload: payload, Signatures: []trustcatalog.Signature{{KeyID: key.ID, Signature: ed25519.Sign(private, append([]byte(trustcatalog.Schema+"\x00"), payload...))}}})
}

func candidateD7Fixture(t *testing.T) (candidateFixture, []byte) {
	t.Helper()
	f := newCandidateFixture(t, false)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate isolated catalogue fixture")
	}
	key := trustcatalog.Key{ID: trustcatalog.KeyID(public), PublicKey: public}
	now := time.Now().Unix()
	document := trustcatalog.Document{Schema: trustcatalog.Schema, StoreID: f.anchor.StoreID, Generation: 1, NotBeforeUnix: now - 30, NotAfterUnix: now + 1200, RootKeys: []trustcatalog.Key{key}, Threshold: 1, Approvers: []trustcatalog.Key{}, Grants: []trustcatalog.Grant{}, PolicyFloors: map[string]uint64{}, RevokedKeys: []string{}, RevokedApprovals: []string{}, RevokedManifests: []string{}}
	f.catalogue = candidateD7Signed(t, document, key, private)
	f.anchor = trustcatalog.Anchor{StoreID: document.StoreID, InitialSHA256: candidateHash(f.catalogue), Keys: []trustcatalog.Key{key}, Threshold: 1}
	candidatePrivateFile(t, f.config.AnchorFile, candidateJSON(t, f.anchor))
	store, err := truststate.Create(context.Background(), f.config.StorePath, f.anchor, f.catalogue)
	if err != nil {
		t.Fatal("create isolated managed state", err)
	}
	state, inspectErr := store.Inspect(context.Background())
	closeErr := store.Close()
	if inspectErr != nil || closeErr != nil {
		t.Fatal("close isolated initial state", inspectErr, closeErr)
	}
	f.sequence = state.Sequence
	document.Generation = 2
	document.RevokedManifests = []string{"sha256:" + strings.Repeat("e", 64)}
	return f, candidateD7Signed(t, document, key, private)
}

func candidateD7Write(t *testing.T, f candidateFixture) {
	t.Helper()
	// Unlike the original default-locked fixture helper, these tests explicitly
	// opt in to writes and refresh. No production configuration is written.
	candidatePrivateFile(t, f.file, candidateJSON(t, f.config))
}

func candidateD7Start(t *testing.T, f candidateFixture) (string, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, f.file, func(network, address string) (net.Listener, error) {
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
				t.Error("candidate did not stop gracefully")
			}
		case <-time.After(12 * time.Second):
			t.Error("candidate background work did not join")
		}
	}
	t.Cleanup(stop)
	select {
	case address := <-ready:
		return address, stop
	case <-done:
		stopped = true
		cancel()
		t.Fatal("candidate failed before listener")
	case <-time.After(5 * time.Second):
		t.Fatal("candidate listener did not start")
	}
	return "", stop
}

func candidateD7Status(t *testing.T, client *http.Client, address string, f candidateFixture) imagetrust.Status {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, "http://"+address+"/api/v1/image-trust", nil)
	if err != nil {
		t.Fatal("build isolated status request")
	}
	request.Header.Set("Authorization", "Bearer "+f.token)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal("isolated status request failed")
	}
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || response.StatusCode != http.StatusOK {
		t.Fatal("isolated status response failed")
	}
	if bytes.Contains(raw, []byte(f.token)) || f.config.RefreshURL != "" && bytes.Contains(raw, []byte(f.config.RefreshURL)) || bytes.Contains(raw, []byte("BEGIN PRIVATE KEY")) {
		t.Fatal("candidate status exposed excluded material")
	}
	var status imagetrust.Status
	if json.Unmarshal(raw, &status) != nil || status.Authorization != "BLOCKED" || status.DeviceActionsExecuted || status.StoreID != f.anchor.StoreID {
		t.Fatal("invalid advisory candidate status")
	}
	return status
}

func TestCandidateD7RefreshConfigurationFailsClosed(t *testing.T) {
	for _, name := range []string{"default-off", "explicit-default-durations", "disabled-with-url", "write-locked", "missing-url", "missing-ip", "missing-spki", "missing-ca", "relative-ca", "bad-ca", "negative-interval", "overflow-duration", "noncanonical-json"} {
		t.Run(name, func(t *testing.T) {
			f := newCandidateFixture(t, true)
			if name == "default-off" {
				client, err := configuredRefresh(f.config)
				if err != nil || client != nil {
					t.Fatal("default started automatic refresh")
				}
				return
			}
			f.config.WritesEnabled = true
			f.config.RefreshEnabled = true
			f.config.RefreshURL = "https://refresh.fixture.invalid/feed"
			f.config.RefreshIP = "127.0.0.1"
			f.config.RefreshSPKI = "sha256:" + strings.Repeat("a", 64)
			f.config.RefreshCAFile = f.config.RegistryCAFile
			if name == "explicit-default-durations" {
				client, err := configuredRefresh(f.config)
				if err != nil || client == nil || client.Interval() != time.Minute || client.MaxAge() != 5*time.Minute || client.Timeout() != 30*time.Second {
					t.Fatal("explicit refresh configuration lost bounded defaults")
				}
				return
			}
			switch name {
			case "disabled-with-url":
				f.config.RefreshEnabled = false
			case "write-locked":
				f.config.WritesEnabled = false
			case "missing-url":
				f.config.RefreshURL = ""
			case "missing-ip":
				f.config.RefreshIP = ""
			case "missing-spki":
				f.config.RefreshSPKI = ""
			case "missing-ca":
				f.config.RefreshCAFile = ""
			case "relative-ca":
				f.config.RefreshCAFile = "relative-refresh-ca.pem"
			case "bad-ca":
				f.config.RefreshCAFile = filepath.Join(filepath.Dir(f.file), "bad-refresh-ca.pem")
				candidatePrivateFile(t, f.config.RefreshCAFile, []byte("not a certificate"))
			case "negative-interval":
				f.config.RefreshIntervalSeconds = -1
			case "overflow-duration":
				f.config.RefreshMaxAgeSeconds = 1<<63 - 1
			}
			candidateD7Write(t, f)
			if name == "noncanonical-json" {
				raw, err := os.ReadFile(f.file)
				if err != nil {
					t.Fatal("read configuration fixture")
				}
				candidatePrivateFile(t, f.file, bytes.Replace(raw, []byte(`"refreshEnabled":`), []byte(`"RefreshEnabled":`), 1))
			}
			listened := false
			if err := run(context.Background(), f.file, func(string, string) (net.Listener, error) { listened = true; return nil, errors.New("must not listen") }); err != errConfiguration || listened {
				t.Fatal("unsafe automatic refresh configuration reached listener")
			}
		})
	}
}

func TestCandidateD7AutomaticTLSRefreshAndRestart(t *testing.T) {
	f, next := candidateD7Fixture(t)
	var requests atomic.Int64
	var insecure atomic.Bool
	feed := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.TLS == nil {
			insecure.Store(true)
		}
		if r.Method != http.MethodGet || r.URL.Path != "/feed/latest.json" || r.Header.Get("Authorization") != "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(next)))
		_, _ = w.Write(next)
	}))
	t.Cleanup(feed.Close)
	certificate := feed.Certificate()
	f.config.WritesEnabled = true
	f.config.RefreshEnabled = true
	f.config.RefreshURL = feed.URL + "/feed"
	f.config.RefreshIP = "127.0.0.1"
	f.config.RefreshSPKI = candidateHash(certificate.RawSubjectPublicKeyInfo)
	f.config.RefreshCAFile = filepath.Join(filepath.Dir(f.file), "refresh-ca.pem")
	f.config.RefreshIntervalSeconds = 1
	f.config.RefreshMaxAgeSeconds = 3
	f.config.RefreshTimeoutSeconds = 1
	candidatePrivateFile(t, f.config.RefreshCAFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}))
	candidateD7Write(t, f)
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	for restart := 0; restart < 2; restart++ {
		address, stop := candidateD7Start(t, f)
		deadline := time.Now().Add(8 * time.Second)
		for {
			status := candidateD7Status(t, client, address, f)
			if status.Generation == 2 && status.CatalogueSHA256 == candidateHash(next) && status.RevokedManifests == 1 && status.Healthy && status.Fresh && status.RefreshRequired && status.RefreshFresh && status.RefreshLastSuccessUnix > 0 && status.RefreshUntilUnix >= status.RefreshLastSuccessUnix {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("real TLS refresh did not apply signed revocation")
			}
			time.Sleep(10 * time.Millisecond)
		}
		stop()
		before := requests.Load()
		time.Sleep(40 * time.Millisecond)
		if requests.Load() != before || insecure.Load() {
			t.Fatal("refresh survived shutdown or used plaintext")
		}
		store, err := truststate.Open(context.Background(), f.config.StorePath, f.anchor)
		if err != nil {
			t.Fatal("candidate retained durable state lock")
		}
		state, inspectErr := store.Inspect(context.Background())
		closeErr := store.Close()
		if inspectErr != nil || closeErr != nil || state.Catalogue.Generation != 2 || state.Catalogue.SHA256 != candidateHash(next) || state.LedgerUsed != 0 {
			t.Fatal("refresh did not persist or created grants")
		}
		audit, err := evidence.Open(f.config.AuditDir)
		if err != nil {
			t.Fatal("candidate retained audit lock")
		}
		report, verifyErr := audit.Verify()
		closeErr = audit.Close()
		if verifyErr != nil || closeErr != nil || !report.Valid || report.Count == 0 {
			t.Fatal("automatic update has no durable valid audit")
		}
	}
	if requests.Load() < 2 {
		t.Fatal("restart did not perform a new trusted fetch")
	}
}

func TestCandidateD7RefreshCancellationJoinsBeforeClose(t *testing.T) {
	f, _ := candidateD7Fixture(t)
	entered := make(chan struct{}, 1)
	closed := make(chan struct{}, 1)
	feed := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-r.Context().Done()
		select {
		case closed <- struct{}{}:
		default:
		}
	}))
	t.Cleanup(feed.Close)
	f.config.WritesEnabled, f.config.RefreshEnabled = true, true
	f.config.RefreshURL, f.config.RefreshIP = feed.URL, "127.0.0.1"
	f.config.RefreshSPKI = candidateHash(feed.Certificate().RawSubjectPublicKeyInfo)
	f.config.RefreshCAFile = filepath.Join(filepath.Dir(f.file), "refresh-ca.pem")
	f.config.RefreshTimeoutSeconds = 30
	candidatePrivateFile(t, f.config.RefreshCAFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: feed.Certificate().Raw}))
	candidateD7Write(t, f)
	_, stop := candidateD7Start(t, f)
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("candidate did not begin real HTTPS fetch")
	}
	started := time.Now()
	stop()
	if time.Since(started) >= 5*time.Second {
		t.Fatal("candidate waited for request timeout instead of cancellation")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("HTTPS request survived joined candidate shutdown")
	}
	store, err := truststate.Open(context.Background(), f.config.StorePath, f.anchor)
	if err != nil {
		t.Fatal("cancelled candidate retained managed lock")
	}
	state, inspectErr := store.Inspect(context.Background())
	closeErr := store.Close()
	if inspectErr != nil || closeErr != nil || state.Catalogue.Generation != 1 || state.Sequence != f.sequence || state.LedgerUsed != 0 {
		t.Fatal("cancelled transport mutated trust state")
	}
}

func TestCandidateD7StartupReconcilesDurableUpdateWithoutReexecution(t *testing.T) {
	for _, stage := range []string{"intent", "prepared-audit", "committed", "result-audit"} {
		t.Run(stage, func(t *testing.T) {
			f, next := candidateD7Fixture(t)
			ctx := context.Background()
			store, err := truststate.Open(ctx, f.config.StorePath, f.anchor)
			if err != nil {
				t.Fatal("open isolated recovery state")
			}
			audit, err := evidence.Open(f.config.AuditDir)
			if err != nil {
				_ = store.Close()
				t.Fatal("open isolated recovery audit")
			}
			scope := authz.ResourceScope{TenantID: f.config.TenantID, SiteID: f.config.SiteID, ObjectType: "image-trust", ObjectID: f.anchor.StoreID, Environment: f.config.Environment}
			report, err := audit.Verify()
			if err != nil || !report.Valid {
				t.Fatal("invalid initial recovery evidence")
			}
			op := truststate.Operation{ID: strings.Repeat("b", 32), ActorID: "candidate-admin", ScopeSHA256: candidateHash(candidateJSON(t, scope)), Kind: "update", Data: map[string]string{"catalogueSHA256": candidateHash(next)}, AuditBaseCount: report.Count, AuditBaseHash: report.LastHash}
			if err := store.PrepareOperation(ctx, op); err != nil {
				t.Fatal("persist recovery intent", err)
			}
			if stage != "intent" {
				prepared, created, err := audit.AppendOnce(evidence.EvidenceEvent{TraceID: op.ID, ActorID: op.ActorID, Action: "image_trust.update", Target: "image-trust/" + f.anchor.StoreID, Result: "prepared", Data: op.Data}, "image-trust/"+op.ID+"/prepared")
				if err != nil || !created || store.BindPreparedAudit(ctx, op.ID, prepared.Hash) != nil {
					t.Fatal("persist prepared evidence")
				}
			}
			if stage == "committed" || stage == "result-audit" {
				if err := store.UpdateTracked(ctx, next, op.ID); err != nil {
					t.Fatal("commit signed update atomically", err)
				}
			}
			if stage == "result-audit" {
				_, created, err := audit.AppendOnce(evidence.EvidenceEvent{TraceID: op.ID, ActorID: op.ActorID, Action: "image_trust.update", Target: "image-trust/" + f.anchor.StoreID, Result: "completed", Data: map[string]string{"catalogueSHA256": candidateHash(next)}}, "image-trust/"+op.ID+"/result")
				if err != nil || !created {
					t.Fatal("persist result before journal acknowledgement")
				}
			}
			if audit.Close() != nil || store.Close() != nil {
				t.Fatal("close interrupted-operation fixtures")
			}
			candidateD7Write(t, f) // Writes remain disabled; reconciliation still precedes listening.
			transport := &http.Transport{Proxy: nil}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
			for restart := 0; restart < 2; restart++ {
				address, stop := candidateD7Start(t, f)
				status := candidateD7Status(t, client, address, f)
				wantGeneration, wantHash := uint64(1), candidateHash(f.catalogue)
				if stage == "committed" || stage == "result-audit" {
					wantGeneration, wantHash = 2, candidateHash(next)
				}
				wantRecovered := 1
				if restart == 1 {
					wantRecovered = 0
				}
				if status.Generation != wantGeneration || status.CatalogueSHA256 != wantHash || status.LedgerEntries != 0 || status.RecoveryCompleted != wantRecovered || !status.Healthy || status.RefreshRequired {
					t.Fatal("startup recovery repeated domain mutation or did not reconcile audit")
				}
				stop()
			}
			store, err = truststate.Open(ctx, f.config.StorePath, f.anchor)
			if err != nil {
				t.Fatal("reopen acknowledged state")
			}
			entries, journalErr := store.Journal(ctx)
			closeErr := store.Close()
			if journalErr != nil || closeErr != nil || len(entries) != 1 || !entries[0].Acknowledged || entries[0].ResultAuditHash == "" {
				t.Fatal("recovery acknowledgement not durable")
			}
			audit, err = evidence.Open(f.config.AuditDir)
			if err != nil {
				t.Fatal("reopen reconciled audit")
			}
			report, verifyErr := audit.Verify()
			closeErr = audit.Close()
			if verifyErr != nil || closeErr != nil || !report.Valid || report.Count != 2 {
				t.Fatal("restart duplicated or failed audit delivery")
			}
		})
	}
}

func TestCandidateD7MaintenanceStopsOnCorruptAuditWithoutRepair(t *testing.T) {
	f := newCandidateFixture(t, true)
	candidateD7Write(t, f)
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, f.file, func(network, address string) (net.Listener, error) {
			listener, err := net.Listen(network, address)
			if err == nil {
				ready <- struct{}{}
			}
			return listener, err
		})
	}()
	stopped := false
	t.Cleanup(func() {
		cancel()
		if !stopped {
			select {
			case <-done:
			case <-time.After(12 * time.Second):
				t.Error("maintenance failure did not release candidate lifecycle")
			}
		}
	})
	select {
	case <-ready:
	case <-done:
		stopped = true
		t.Fatal("maintenance candidate failed before listen")
	case <-time.After(5 * time.Second):
		t.Fatal("maintenance candidate listener did not start")
	}
	checkpoint := filepath.Join(f.config.AuditDir, "checkpoint.json")
	corrupt := []byte(`{"checkpoint":"deliberately-invalid-isolated-fixture"}`)
	candidatePrivateFile(t, checkpoint, corrupt)
	select {
	case err := <-done:
		stopped = true
		if err != errConfiguration {
			t.Fatal("background integrity failure was treated as graceful success")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("real 15-second audit maintenance did not stop damaged candidate")
	}
	raw, err := os.ReadFile(checkpoint)
	if err != nil || !bytes.Equal(raw, corrupt) {
		t.Fatal("background maintenance repaired or replaced corrupt checkpoint")
	}
	store, err := truststate.Open(context.Background(), f.config.StorePath, f.anchor)
	if err != nil {
		t.Fatal("maintenance failure retained managed state lock")
	}
	state, inspectErr := store.Inspect(context.Background())
	closeErr := store.Close()
	if inspectErr != nil || closeErr != nil || state.Sequence != f.sequence || state.LedgerUsed != 0 || state.Catalogue.Generation != 1 {
		t.Fatal("audit corruption maintenance changed domain state")
	}
	listened := false
	if err := run(context.Background(), f.file, func(string, string) (net.Listener, error) { listened = true; return nil, errConfiguration }); err != errConfiguration || listened {
		t.Fatal("restart accepted corrupt checkpoint")
	}
}
