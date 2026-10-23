//go:build linux && probereadbacklab

package probereadbacklab

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"chengwang/internal/authn"
	"chengwang/internal/authz"
	"chengwang/internal/probe"
	"chengwang/internal/probeview"
)

var rootPattern = regexp.MustCompile(`^/tmp/chengwang-probe-readback-([a-f0-9]{32})$`)

type certificateCorpus struct {
	DotCARaw      []byte `json:"dotCARaw"`
	TargetCARaw   []byte `json:"targetCARaw"`
	APICARaw      []byte `json:"apiCARaw"`
	DotLeafRaw    []byte `json:"dotLeafRaw"`
	TargetLeafRaw []byte `json:"targetLeafRaw"`
	APILeafRaw    []byte `json:"apiLeafRaw"`
}

func TestProbeReadbackLabFixture(t *testing.T) {
	defer func() {
		if e := recover(); e != nil {
			step := "INTERNAL"
			if r, ok := e.(rejected); ok {
				step = r.step
			}
			t.Fatalf("PROBE_READBACK_LAB=FAIL step=%s raw_input_suppressed=true", step)
		}
	}()
	demand(os.Geteuid() == 10001 && os.Getegid() == 10001, "DRIVER_IDENTITY")
	root, commit, action, phase := os.Getenv("CHENGWANG_PROBE_LAB_ROOT"), os.Getenv("CHENGWANG_PROBE_LAB_COMMIT"), os.Getenv("CHENGWANG_PROBE_LAB_ACTION"), os.Getenv("CHENGWANG_PROBE_LAB_PHASE")
	m := rootPattern.FindStringSubmatch(root)
	demand(m != nil && regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(commit), "DRIVER_ARGUMENTS")
	metadata(root, true)
	r := map[string]any{"schema": "chengwang.probe-readback-driver/v1", "sourceCommit": commit, "fixtureId": m[1], "action": action, "phase": phase, "authorization": "BLOCKED", "production": false, "deviceActionsExecuted": false}
	name := action
	switch action {
	case "prepare":
		demand(phase == "", "DRIVER_PHASE")
		prepare(root, r)
	case "collect":
		demand(phase == "first" || phase == "final", "DRIVER_PHASE")
		name += "-" + phase
		collect(root, phase, r)
	case "verify":
		demand(phase == "fresh" || phase == "restarted" || phase == "expired", "DRIVER_PHASE")
		name += "-" + phase
		verify(root, phase, r)
	default:
		demand(false, "DRIVER_ACTION")
	}
	writeFile(filepath.Join(root, "product-probe-readback-"+name+".json"), append(encoded(r), '\n'))
	fmt.Printf("PROBE_READBACK_LAB=PASS action=%s phase=%s authorization=BLOCKED production=false\n", action, phase)
}

func certificateKey(name string) (any, any) {
	// Chromium does not advertise Ed25519 certificate signatures by default.
	// The API fixture must use a normally supported certificate, not a browser
	// verification bypass. Probe target/DoT fixtures keep their original keys.
	if name == "api" {
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		demand(e == nil, "CERTIFICATE_KEY")
		return &key.PublicKey, key
	}
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	demand(e == nil, "CERTIFICATE_KEY")
	return pub, key
}

func certificate(now time.Time, name string, dns []string, ips []net.IP) ([]byte, []byte, []byte) {
	pub, key := certificateKey(name)
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	demand(e == nil, "CERTIFICATE_SERIAL")
	ca := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "probe-lab-" + name + "-ca"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, e := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	demand(e == nil, "CERTIFICATE_CA")
	leafPub, leafKey := certificateKey(name)
	leaf := &x509.Certificate{SerialNumber: new(big.Int).Add(serial, big.NewInt(1)), Subject: pkix.Name{CommonName: "probe-lab-" + name}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, DNSNames: dns, IPAddresses: ips, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, e := x509.CreateCertificate(rand.Reader, leaf, ca, leafPub, key)
	demand(e == nil, "CERTIFICATE_LEAF")
	private, e := x509.MarshalPKCS8PrivateKey(leafKey)
	demand(e == nil, "CERTIFICATE_PRIVATE")
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
}

func prepare(root string, out map[string]any) {
	entries, e := os.ReadDir(root)
	demand(e == nil && len(entries) == 0, "PREPARE_REQUIRES_EMPTY_ROOT")
	for _, dir := range []string{"wire", "spool", "ledger", "data"} {
		mkdir(filepath.Join(root, dir))
	}
	now := time.Now().UTC()
	var corpus certificateCorpus
	var key []byte
	corpus.DotCARaw, corpus.DotLeafRaw, key = certificate(now, "dot", []string{"dot.probe.example"}, nil)
	writeFile(filepath.Join(root, "dot-ca.pem"), corpus.DotCARaw)
	writeFile(filepath.Join(root, "wire/dot-cert.pem"), corpus.DotLeafRaw)
	writeFile(filepath.Join(root, "wire/dot-key.private.pem"), key)
	corpus.TargetCARaw, corpus.TargetLeafRaw, key = certificate(now, "target", []string{"pass.probe.example", "restricted.probe.example", "limited.probe.example"}, nil)
	writeFile(filepath.Join(root, "target-ca.pem"), corpus.TargetCARaw)
	writeFile(filepath.Join(root, "wire/https-cert.pem"), corpus.TargetLeafRaw)
	writeFile(filepath.Join(root, "wire/https-key.private.pem"), key)
	corpus.APICARaw, corpus.APILeafRaw, key = certificate(now, "api", nil, []net.IP{net.ParseIP("127.0.0.1")})
	writeFile(filepath.Join(root, "api-ca.pem"), corpus.APICARaw)
	writeFile(filepath.Join(root, "api-cert.pem"), corpus.APILeafRaw)
	writeFile(filepath.Join(root, "api-key.private.pem"), key)
	catalog := probe.Catalog{Schema: probe.CatalogSchemaV1, Revision: "probe-readback-lab-v1", Agent: probe.AgentSpec{ID: "probe-readback-agent", Independence: probe.IndependenceP1, AdvisoryOnly: true}, Paths: []probe.Path{{ID: "direct", Kind: probe.PathKindDirect}}, Probes: []probe.Target{}}
	for _, id := range []string{"pass", "restricted", "limited"} {
		target := probe.Target{ID: id, PathID: "direct", Kind: probe.ProbeHTTPS, Host: id + ".probe.example", Port: 443, RequestPath: "/health", Method: "GET", ExpectedStatus: []int{200}, IntervalSeconds: 60, TimeoutSeconds: 2, TTLSeconds: 120, MaxBodyBytes: 4096}
		if id == "pass" {
			target.RequiredMarker = "chengwang-probe-pass-v1"
		}
		catalog.Probes = append(catalog.Probes, target)
	}
	raw := encoded(catalog)
	validated, e := probe.ParseCatalogBytes(raw)
	demand(e == nil, "CATALOG_PREPARE")
	writeFile(filepath.Join(root, "catalog.json"), raw)
	identities := authn.File{Version: authn.FileVersion, Identities: []authn.Identity{}}
	for _, name := range []string{"viewer", "foreign"} {
		token, hash, e := authn.GenerateToken(32)
		demand(e == nil, "IDENTITY_TOKEN")
		site := "probe-lab-site"
		if name == "foreign" {
			site = "other-site"
		}
		scope := authz.ResourceScope{TenantID: "probe-lab-tenant", SiteID: site, ObjectType: "control-plane", ObjectID: "probe-readback", Environment: "shadow"}
		identities.Identities = append(identities.Identities, authn.Identity{TokenID: "lab-" + name, TokenHash: hash, Principal: authz.Principal{ID: "lab-" + name, TenantID: "probe-lab-tenant", Roles: []authz.Role{authz.RoleViewer}, AllowedScopes: []authz.ResourceScope{scope}}})
		writeFile(filepath.Join(root, name+"-token.private"), []byte(token))
	}
	writeFile(filepath.Join(root, "identities.private.json"), encoded(identities))
	env := map[string]string{"CHENGWANG_ADDR": "127.0.0.1:17861", "CHENGWANG_DATA_DIR": filepath.Join(root, "data"), "CHENGWANG_IDENTITIES_FILE": filepath.Join(root, "identities.private.json"), "CHENGWANG_TLS_CERT_FILE": filepath.Join(root, "api-cert.pem"), "CHENGWANG_TLS_KEY_FILE": filepath.Join(root, "api-key.private.pem"), "CHENGWANG_MANAGEMENT_TENANT_ID": "probe-lab-tenant", "CHENGWANG_MANAGEMENT_SITE_ID": "probe-lab-site", "CHENGWANG_MANAGEMENT_OBJECT_ID": "probe-readback", "CHENGWANG_MODE": "shadow", "CHENGWANG_PROBE_READ_ENABLED": "true", "CHENGWANG_PROBE_CATALOG_FILE": filepath.Join(root, "catalog.json"), "CHENGWANG_PROBE_SPOOL_DIR": filepath.Join(root, "spool"), "CHENGWANG_PROBE_POLL_INTERVAL": "1s", "CHENGWANG_PROBE_CACHE_MAX_AGE": "30s"}
	writeFile(filepath.Join(root, "server-env.private.json"), encoded(env))
	args := []string{"--catalog", filepath.Join(root, "catalog.json"), "--spool-dir", filepath.Join(root, "spool"), "--ledger-dir", filepath.Join(root, "ledger"), "--dot-upstream", "127.0.0.1:1853", "--dot-server-name", "dot.probe.example", "--dot-ca", filepath.Join(root, "dot-ca.pem"), "--resolver-timeout", "2s", "--runner-timeout", "2s", "--concurrency", "1", "--queue-size", "3", "--starts-per-minute", "6"}
	writeFile(filepath.Join(root, "agent-args.private.json"), encoded(args))
	out["catalogRaw"], out["catalogDigest"], out["certificates"] = raw, validated.Digest, corpus
}

func catalogAt(root string) probe.Catalog {
	c, e := probe.ReadCatalogSecure(context.Background(), filepath.Join(root, "catalog.json"), probe.SecureFileOwner{UID: 10001, GID: 10001})
	demand(e == nil, "CATALOG_READ")
	return c
}
func settled(s ledgerDisk, results []probe.ProbeResult, seen map[string]bool) {
	byStart := map[string]probe.ProbeResult{}
	for _, r := range results {
		byStart[r.EvidenceRef] = r
	}
	for _, start := range s.Starts {
		r, ok := byStart[start.StartID]
		demand(ok && start.ProbeID == r.ProbeID && start.SettledAt != nil && start.ResultRunID == r.RunID && start.SettledAt.Equal(r.CompletedAt) && !r.AttemptedAt.Before(start.StartedAt), "LEDGER_SETTLEMENT")
		seen[r.RunID] = true
	}
	for _, rate := range s.RateLimits {
		matched := false
		for _, r := range results {
			if rate.SourceRunID == r.RunID {
				matched = r.ProbeID == "limited" && rate.ProbeID == r.ProbeID && rate.ObservedAt.Equal(r.CompletedAt) && rate.NotBefore.Equal(r.CompletedAt.Add(30*time.Second))
			}
		}
		demand(matched, "LEDGER_RATE_LIMIT")
	}
}

func tryCollect(root, phase string, catalog probe.Catalog) (result map[string]any, ok bool) {
	defer func() {
		if e := recover(); e != nil {
			if _, expected := e.(rejected); expected {
				result = nil
				ok = false
			} else {
				panic(e)
			}
		}
	}()
	now := time.Now().UTC()
	before := sourceTree(root)
	results := readResults(before, catalog, now)
	want, sequence := 3, uint64(7)
	if phase == "final" {
		want, sequence = 6, 13
	}
	demand(len(results) == want, "COLLECT_RESULT_COUNT")
	counts := map[string]int{}
	for _, r := range results {
		counts[r.ProbeID]++
	}
	for _, id := range []string{"pass", "restricted", "limited"} {
		demand(counts[id] == want/3, "COLLECT_TARGET_COUNT")
	}
	report, e := probe.ReadStoreSecure(context.Background(), filepath.Join(root, "spool"), probe.SecureReadOptions{ReadOptions: probe.ReadOptions{Catalog: catalog, Limit: 200, Now: now}, OwnerUID: 10001, OwnerGID: 10001})
	demand(e == nil && report.Healthy && report.Rejected == 0 && len(report.Results) == want && same(report.Results, results), "COLLECT_SECURE_READER")
	ledger := readLedger(before, root, catalog, now)
	demand(ledger.Sequence == sequence, "COLLECT_LEDGER_SEQUENCE")
	seen := map[string]bool{}
	settled(ledger, results, seen)
	if phase == "first" {
		demand(len(ledger.Starts) == 3 && len(seen) == 3, "COLLECT_FIRST_SETTLED")
	} else {
		var old struct {
			Schema                string       `json:"schema"`
			SourceCommit          string       `json:"sourceCommit"`
			FixtureID             string       `json:"fixtureId"`
			Action                string       `json:"action"`
			Phase                 string       `json:"phase"`
			Authorization         string       `json:"authorization"`
			Production            bool         `json:"production"`
			DeviceActionsExecuted bool         `json:"deviceActionsExecuted"`
			ObservedAt            time.Time    `json:"observedAt"`
			SpoolSegments         []rawFile    `json:"spoolSegments"`
			LedgerSnapshots       []rawFile    `json:"ledgerSnapshots"`
			SourceFiles           []sourceFile `json:"sourceFiles"`
			SourceTreeSHA256      string       `json:"sourceTreeSHA256"`
		}
		decode(readFile(filepath.Join(root, "product-probe-readback-collect-first.json"), 1<<20), &old)
		demand(old.Schema == "chengwang.probe-readback-driver/v1" && old.Action == "collect" && old.Phase == "first" && old.SourceCommit == os.Getenv("CHENGWANG_PROBE_LAB_COMMIT") && old.FixtureID == rootPattern.FindStringSubmatch(root)[1] && old.Authorization == "BLOCKED" && !old.Production && !old.DeviceActionsExecuted && len(old.LedgerSnapshots) == 1, "COLLECT_FIRST_BINDING")
		var first ledgerDisk
		decode(old.LedgerSnapshots[0].Raw, &first)
		demand(first.Sequence == 7 && first.Digest == "sha256:"+digest(encoded(first.ledgerPayload)), "COLLECT_FIRST_DIGEST")
		settled(first, results, seen)
		demand(len(seen) == 6, "COLLECT_ALL_SETTLED")
		for _, file := range old.SpoolSegments {
			raw, exists := before.Raw["spool/segments/"+file.Name]
			demand(exists && bytes.Equal(raw, file.Raw) && digest(file.Raw) == file.SHA256, "COLLECT_IMMUTABLE_PREFIX")
		}
	}
	after := sourceTree(root)
	demand(before.SHA == after.SHA, "COLLECT_TREE_CHANGED")
	return map[string]any{"observedAt": now, "spoolSegments": rawEntries(before, "spool/segments/"), "ledgerSnapshots": rawEntries(before, "ledger/snapshots/"), "sourceFiles": before.Files, "sourceTreeSHA256": before.SHA}, true
}
func collect(root, phase string, out map[string]any) {
	catalog := catalogAt(root)
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if result, ok := tryCollect(root, phase, catalog); ok {
			for key, value := range result {
				out[key] = value
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	demand(false, "COLLECT_DEADLINE")
}

type requestRecord struct {
	Name       string `json:"name"`
	HTTPStatus int    `json:"httpStatus"`
}

func apiRead(client *http.Client, path, token string) (int, []byte) {
	r, e := http.NewRequest(http.MethodGet, "https://127.0.0.1:17861"+path, nil)
	demand(e == nil, "API_REQUEST")
	r.Header.Set("Accept", "application/json")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	response, e := client.Do(r)
	demand(e == nil, "API_NORMAL_TLS")
	defer response.Body.Close()
	demand(response.TLS != nil && len(response.TLS.VerifiedChains) > 0 && strings.HasPrefix(response.Header.Get("Content-Type"), "application/json"), "API_TLS_IDENTITY")
	raw, e := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	demand(e == nil && len(raw) <= 1<<20, "API_BODY_LIMIT_EOF")
	return response.StatusCode, raw
}

func verify(root, phase string, out map[string]any) {
	catalog := catalogAt(root)
	before := sourceTree(root)
	now := time.Now().UTC()
	results := readResults(before, catalog, now)
	demand(len(results) == 6, "VERIFY_RESULTS")
	var final map[string]json.RawMessage
	decode(readFile(filepath.Join(root, "product-probe-readback-collect-final.json"), 1<<20), &final)
	var finalSHA string
	decode(final["sourceTreeSHA256"], &finalSHA)
	demand(before.SHA == finalSHA, "VERIFY_ORIGINAL_TREE")
	offline, e := probe.ValidateStateSnapshot(filepath.Join(root, "spool"), filepath.Join(root, "ledger"), probe.StateValidationOptions{Catalog: catalog, Now: now, ExpectedLedgerWriterDirectory: filepath.Join(root, "ledger"), ExpectedOwnerUID: 10001, ExpectedOwnerGID: 10001, EnforceExpectedOwner: true})
	demand(e == nil && offline.SpoolResults == 6 && offline.LatestSequence == 13 && offline.LatestInFlight == 0 && offline.RelationshipComplete && offline.MissingRetainedEvidence == 0 && offline.ReadOnlyValidation && offline.SecurityMetadataVerified, "VERIFY_OFFLINE")
	pool := x509.NewCertPool()
	demand(pool.AppendCertsFromPEM(readFile(filepath.Join(root, "api-ca.pem"), 64<<10)), "API_CA")
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: 3 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	requests := []requestRecord{}
	var status probeview.Status
	var statusRaw []byte
	deadline := time.Now().Add(8 * time.Second)
	for {
		code, raw := apiRead(client, "/api/v1/probes/status", "")
		requests = append(requests, requestRecord{"status", code})
		demand(code == 200, "API_STATUS")
		decode(raw, &status)
		statusRaw = raw
		if phase == "expired" {
			if status.Coverage.ExpiredTotal == 6 && status.Coverage.RetainedSamples == 0 {
				break
			}
		} else if status.Configured && status.Running && status.ClockHealthy && status.StorageHealthy && status.State == "ready" && status.Coverage.RetainedSamples == 6 {
			break
		}
		demand(time.Now().Before(deadline), "API_CACHE_DEADLINE")
		time.Sleep(100 * time.Millisecond)
	}
	code, denied := apiRead(client, "/api/v1/probes/details", "")
	requests = append(requests, requestRecord{"unauthenticated-details", code})
	demand(code == 401, "API_AUTHENTICATION")
	var denial struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	decode(denied, &denial)
	demand(denial.Code == "unauthorized", "API_AUTHENTICATION_BODY")
	code, denied = apiRead(client, "/api/v1/probes/details", string(readFile(filepath.Join(root, "foreign-token.private"), 512)))
	requests = append(requests, requestRecord{"foreign-scope-details", code})
	demand(code == 403, "API_SCOPE")
	decode(denied, &denial)
	demand(denial.Code == "forbidden", "API_SCOPE_BODY")
	var detail probeview.Details
	var detailRaw []byte
	for {
		code, detailRaw = apiRead(client, "/api/v1/probes/details", string(readFile(filepath.Join(root, "viewer-token.private"), 512)))
		requests = append(requests, requestRecord{"details", code})
		demand(code == 200, "API_DETAILS")
		decode(detailRaw, &detail)
		if same(status, detail.Status) {
			break
		}
		// Separate GETs are not an atomic transaction. Retry a generation
		// crossing rather than accepting a mixed status/details proof.
		demand(time.Now().Before(deadline), "API_STABLE_CACHE_DEADLINE")
		code, statusRaw = apiRead(client, "/api/v1/probes/status", "")
		requests = append(requests, requestRecord{"status", code})
		demand(code == 200, "API_STATUS")
		decode(statusRaw, &status)
	}
	demand(detail.CatalogDigest == catalog.Digest && detail.AgentID == catalog.Agent.ID && detail.Independence == probe.IndependenceP1 && detail.AdvisoryOnly && len(detail.Targets) == 3, "API_DETAIL_BINDING")
	demand(status.Schema == "chengwang.probe-view-status/v1" && status.AdvisoryOnly && status.Coverage.DeclaredTargets == 3 && status.Coverage.RejectedTotal == 0 && status.StorageHealthy && status.ClockHealthy && detail.Status.StorageHealthy && detail.Status.ClockHealthy, "API_STATUS_BINDING")
	if phase == "expired" {
		latest := time.Time{}
		for _, r := range results {
			demand(!r.ExpiresAt.After(time.Now()), "VERIFY_NATURAL_EXPIRY")
			if r.ExpiresAt.After(latest) {
				latest = r.ExpiresAt
			}
			for _, layer := range []probe.LayerResult{r.Layers.DNS, r.Layers.Connect, r.Layers.TLS, r.Layers.HTTP, r.Layers.Business} {
				if layer.ExpiresAt.After(latest) {
					latest = layer.ExpiresAt
				}
			}
		}
		demand(status.CachedAt != nil && !status.CachedAt.Before(latest) && status.Reason == "evidence_expired" && status.Coverage.ValidTotal == 6 && status.Coverage.EligibleTotal == 0 && status.Coverage.TargetsMissing == 3 && len(detail.Samples) == 0 && detail.Status.Coverage.ExpiredTotal == 6, "API_EXPIRED_SAMPLES")
		for _, target := range detail.Targets {
			demand(target.State == probe.ConclusionUnknown, "API_EXPIRED_TARGET")
		}
	} else {
		demand(len(detail.Samples) == 6 && detail.Status.State == "ready" && detail.Status.Running, "API_FRESH_SAMPLES")
		byRun := map[string]probe.ProbeResult{}
		for _, r := range results {
			byRun[r.RunID] = r
		}
		for _, sample := range detail.Samples {
			r, ok := byRun[sample.RunID]
			demand(ok, "API_ACTUAL_RUN_ID")
			demand(sample.ProbeID == r.ProbeID && sample.PathID == r.PathID && sample.AttemptedAt.Equal(r.AttemptedAt) && sample.CompletedAt.Equal(r.CompletedAt) && sample.ExpiresAt.Equal(r.ExpiresAt) && sample.Conclusion == r.Conclusion && sample.Outcome == r.Outcome && same(sample.HTTPStatus, r.HTTPStatus) && sample.ResponseBytes == r.ResponseBytes, "API_ACTUAL_RESULT")
			demand(same(sample.Layers, r.Layers), "API_ACTUAL_LAYERS")
			delete(byRun, sample.RunID)
		}
		demand(len(byRun) == 0, "API_ALL_RUN_IDS")
		for _, target := range detail.Targets {
			want := probe.ConclusionRestricted
			switch target.ProbeID {
			case "pass":
				want = probe.ConclusionAvailable
				demand(target.ConsecutiveSuccess == 2, "API_TWO_SUCCESSES")
			case "limited":
				want = probe.ConclusionRateLimited
			case "restricted":
			default:
				demand(false, "API_TARGET")
			}
			demand(target.State == want, "API_AGGREGATE")
		}
	}
	after := sourceTree(root)
	demand(before.SHA == after.SHA, "VERIFY_TREE_CHANGED")
	writeFile(filepath.Join(root, "product-probe-readback-api-"+phase+"-status.json"), statusRaw)
	writeFile(filepath.Join(root, "product-probe-readback-api-"+phase+"-details.json"), detailRaw)
	out["observedAt"], out["status"], out["details"], out["requests"], out["offline"], out["sourceFiles"], out["sourceTreeSHA256"] = time.Now().UTC(), status, detail, requests, offline, before.Files, before.SHA
}
