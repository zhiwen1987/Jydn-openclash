//go:build linux && productregistry && productstate

package binding_test

// This fixture seeds public store transactions, never a product constructor or
// a fault hook. Only the separately inspected image performs reconciliation.
import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	verifier "chengwang-image-verifier"
	binding "chengwang/image-binding"
	"chengwang/image-binding/trustcatalog"
	"chengwang/image-binding/truststate"
	"chengwang/internal/authn"
	"chengwang/internal/authz"
	"chengwang/internal/evidence"
	"chengwang/internal/imagetrust"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/sys/unix"
)

const stateBoundary = "ADVISORY_PRODUCT_STATE_FIXTURE"
const stateActor = "d12-state-admin"
const stateForeignActor = "d12-state-foreign"

var stateBoundaries = []string{"after-journal-prepare", "after-prepared-audit", "before-result-audit", "after-journal-outcome", "after-result-audit", "after-journal-ack"}
var stateFaults = []string{"acked-audit-missing", "prepared-audit-missing", "wrong-prefix", "prepared-key-conflict", "result-key-conflict", "wrong-scope", "bad-checkpoint", "later-invalid-acked"}

type stateRawHash struct {
	Bytes  int    `json:"bytes"`
	SHA256 string `json:"sha256"`
}
type stateAuditBinding struct {
	OperationID string                  `json:"operationID"`
	Prepared    *evidence.EvidenceEvent `json:"prepared"`
	Result      *evidence.EvidenceEvent `json:"result"`
}
type stateOffline struct {
	TrustRecordSHA256 string                    `json:"trustRecordSHA256"`
	Inspection        truststate.Inspection     `json:"inspection"`
	Journal           []truststate.JournalEntry `json:"journal"`
	AuditOpen         string                    `json:"auditOpen"`
	Audit             *evidence.VerifyReport    `json:"audit"`
	AuditEvents       []evidence.EvidenceEvent  `json:"auditEvents"`
	AuditBindings     []stateAuditBinding       `json:"auditBindings"`
	AuditLog          stateRawHash              `json:"auditLog"`
	Checkpoint        stateRawHash              `json:"checkpoint"`
}

// Field order and uppercase names intentionally match managed.go's evidence
// projection. These are public getters, not a serialized reusable capability.
type stateSDKProjection struct {
	Schema, Grant, Catalogue                                   string
	Generation                                                 uint64
	Reference, Approval, Manifest, Config, Graph, Bundle, Root string
	ObservedAtUnixNano                                         int64
	ValidUntilUnix                                             int64
}
type stateSDK struct {
	Boundary       string             `json:"boundary"`
	Authorization  string             `json:"authorization"`
	Verified       bool               `json:"verified"`
	PolicyID       string             `json:"policyID"`
	PolicyRevision uint64             `json:"policyRevision"`
	EvidenceSHA256 string             `json:"evidenceSHA256"`
	Projection     stateSDKProjection `json:"projection"`
}
type stateReport struct {
	Schema   string `json:"schema"`
	Action   string `json:"action"`
	Lane     string `json:"lane"`
	Scenario string `json:"scenario"`
	CaseKind string `json:"caseKind"`
	d11Material
	Boundary              string              `json:"boundary"`
	Authority             string              `json:"authority"`
	GraphOrigin           string              `json:"graphOrigin"`
	Authorization         string              `json:"authorization"`
	Production            bool                `json:"production"`
	DeviceActionsExecuted bool                `json:"deviceActionsExecuted"`
	CanonicalScope        authz.ResourceScope `json:"canonicalScope"`
	ConfiguredScope       authz.ResourceScope `json:"configuredScope"`
	Offline               *stateOffline       `json:"offline,omitempty"`
	Status                *imagetrust.Status  `json:"status,omitempty"`
	History               *imagetrust.History `json:"history,omitempty"`
	AuditLog              *stateRawHash       `json:"auditLog,omitempty"`
	Checkpoint            *stateRawHash       `json:"checkpoint,omitempty"`
	SDK                   *stateSDK           `json:"sdk,omitempty"`
}

func stateRequire(t *testing.T, ok bool) {
	t.Helper()
	if !ok {
		_, own, _, _ := runtime.Caller(0)
		if _, file, line, found := runtime.Caller(1); found && file == own {
			fmt.Printf("D12_PRODUCT_STATE_ASSERT_LINE=%d\n", line)
		}
		t.Fatal("isolated product state fixture rejected")
	}
}
func stateIndex(values []string, value string) int {
	for i, candidate := range values {
		if candidate == value {
			return i
		}
	}
	return -1
}
func stateEndpoint(root, lane, scenario, kind string) string {
	return filepath.Join(root, "state", lane, scenario, kind)
}
func stateReportPath(root, lane, scenario, kind, action string) string {
	return filepath.Join(root, "evidence", "product-state-"+lane+"-"+scenario+"-"+kind+"-"+action+".json")
}
func stateScope(storeID string) authz.ResourceScope {
	return authz.ResourceScope{TenantID: "d12-tenant", SiteID: "d12-site", ObjectType: "image-trust", ObjectID: storeID, Environment: "candidate"}
}
func stateNew(info d11Material, lane, scenario, action string) stateReport {
	scope := stateScope(info.StoreID)
	configured := scope
	if scenario == "wrong-scope" {
		configured.SiteID = "other-site"
	}
	caseKind := "healthy"
	if stateIndex(stateFaults, scenario) >= 0 {
		caseKind = "rejected"
	}
	return stateReport{Schema: "chengwang.product-state-action/v1", Action: action, Lane: lane, Scenario: scenario, CaseKind: caseKind,
		d11Material: info, Boundary: stateBoundary, Authority: "EPHEMERAL_TEST_ONLY", GraphOrigin: "NORMAL_TLS_REGISTRY_READBACK_MATCHED_UPLOAD",
		Authorization: "BLOCKED", CanonicalScope: scope, ConfiguredScope: configured}
}
func stateSave(t *testing.T, root string, report stateReport) {
	t.Helper()
	d11Dir(t, filepath.Join(root, "evidence"))
	d11JSON(t, stateReportPath(root, report.Lane, report.Scenario, report.Kind, report.Action), report)
}
func stateLoad(t *testing.T, root, lane, scenario, kind, action string) stateReport {
	t.Helper()
	var report stateReport
	d11Decode(t, d11Read(t, stateReportPath(root, lane, scenario, kind, action), 4<<20), &report)
	expected := stateNew(report.d11Material, lane, scenario, action)
	stateRequire(t, report.Schema == expected.Schema && report.Action == action && report.Lane == lane && report.Scenario == scenario && report.Kind == kind && report.CaseKind == expected.CaseKind && report.Boundary == stateBoundary && report.Authority == expected.Authority && report.GraphOrigin == expected.GraphOrigin && report.Authorization == "BLOCKED" && !report.Production && !report.DeviceActionsExecuted && report.CanonicalScope == expected.CanonicalScope && report.ConfiguredScope == expected.ConfiguredScope)
	return report
}
func statePort(kind string) string {
	if kind == "dsse" {
		return "17842"
	}
	return "17841"
}

func TestProductStateD12Fixture(t *testing.T) {
	root, lane, scenario, kind := os.Getenv("CHENGWANG_STATE_ROOT"), os.Getenv("CHENGWANG_STATE_LANE"), os.Getenv("CHENGWANG_STATE_SCENARIO"), os.Getenv("CHENGWANG_STATE_KIND")
	commit, image, action := os.Getenv("CHENGWANG_STATE_COMMIT"), os.Getenv("CHENGWANG_STATE_IMAGE_ID"), os.Getenv("CHENGWANG_STATE_ACTION")
	stateRequire(t, os.Getuid() == 10001 && os.Geteuid() == 10001 && os.Getgid() == 10001 && os.Getegid() == 10001)
	stateRequire(t, regexp.MustCompile(`^/tmp/chengwang-product-lifecycle-[0-9a-f]{32}$`).MatchString(root))
	stateRequire(t, (lane == "update" || lane == "verify-reserved" || lane == "verify-consumed") && (stateIndex(stateBoundaries, scenario) >= 0 || stateIndex(stateFaults, scenario) >= 0) && (kind == "message-signature" || kind == "dsse"))
	stateRequire(t, regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(commit) && regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(image))
	for _, directory := range []string{root, filepath.Join(root, "state"), filepath.Join(root, "state", lane), filepath.Join(root, "state", lane, scenario)} {
		d11Dir(t, directory)
	}
	stateRequire(t, string(d11Read(t, filepath.Join(root, ".fixture-owner"), 64)) == strings.TrimPrefix(root, "/tmp/chengwang-product-lifecycle-")+"\n")
	stateRequire(t, os.Getenv("CHENGWANG_STATE_ARCHIVE") == filepath.Join(root, "bin", "product-image.private.tar"))
	t.Setenv("CHENGWANG_D11_KIND", kind)
	t.Setenv("CHENGWANG_D11_ARCHIVE", os.Getenv("CHENGWANG_STATE_ARCHIVE"))
	if action == "prepare" {
		statePrepare(t, root, lane, scenario, kind, commit, image)
	} else {
		info := stateInfo(t, root, lane, scenario, kind, commit, image)
		switch action {
		case "seed":
			stateSeed(t, root, lane, scenario, info)
		case "reopen-first", "reopen-second":
			stateReopen(t, root, lane, scenario, action, info)
		case "first-read", "second-read":
			stateObserve(t, root, lane, scenario, action, info)
		default:
			stateRequire(t, false)
		}
	}
	fmt.Printf("D12_PRODUCT_STATE_%s=PASS lane=%s scenario=%s kind=%s authorization=BLOCKED production=false\n", strings.ReplaceAll(strings.ToUpper(action), "-", "_"), lane, scenario, kind)
}

func statePrepare(t *testing.T, root, lane, scenario, kind, commit, image string) {
	t.Helper()
	endpoint := stateEndpoint(root, lane, scenario, kind)
	d11Mkdir(t, endpoint)
	d11Mkdir(t, filepath.Join(endpoint, "data"))
	manifest, config, layers, diffs := d11Archive(t, root, commit, image)
	d11Upload(t, root, endpoint, manifest, config, layers)
	leaf, _ := pem.Decode(d11Read(t, filepath.Join(root, "registry-cert.pem"), 256<<10))
	stateRequire(t, leaf != nil)
	certificate, err := x509.ParseCertificate(leaf.Bytes)
	stateRequire(t, err == nil && certificate.VerifyHostname("registry.fixture.invalid") == nil)
	spki := hashed(certificate.RawSubjectPublicKeyInfo)
	signatureKind := verifier.KindMessageSignature
	if kind == "dsse" {
		signatureKind = verifier.KindDSSE
	}
	bundle, _, trustedRoot, expected, _ := signedBundlePair(t, signatureKind, manifest, append(bytes.Clone(manifest), '\n'), d11Repository)
	m := material{manifest: manifest, config: config, bundle: bundle, root: trustedRoot, repository: d11Repository, reference: d11Repository + "@" + hashed(manifest)}
	approveImage(t, &m, expected, spki)
	var envelope struct {
		Payload   []byte `json:"payload"`
		Signature []byte `json:"signature"`
	}
	d11Decode(t, m.approval, &envelope)
	var approval map[string]any
	stateRequire(t, json.Unmarshal(envelope.Payload, &approval) == nil)
	approval["policyID"] = "d12-state-" + lane
	envelope.Payload = encode(t, approval)
	m.approval = encode(t, envelope)
	managed := newManagedMaterial(t, m)
	doc2 := managed.document
	doc2.Generation = 2
	cat2 := signManagedCatalogue(t, doc2, managed.rootKey)
	replayed, err := trustcatalog.Replay(managed.anchor, [][]byte{managed.catalogue, cat2})
	stateRequire(t, err == nil && replayed.Generation() == 2 && replayed.ValidAt(time.Now()))
	policy := d11Policy{Name: "original", PolicyID: "d12-state-" + lane, GrantID: managed.document.Grants[0].ID, ApprovalSHA256: managed.trust.PolicySHA256, ApprovalEnvelopeSHA256: hashed(managed.approval), BundleSHA256: hashed(bundle), BundleArtifactSHA256: hashed(manifest), TrustedRootSHA256: hashed(trustedRoot), RegistrySPKI: spki}
	for name, raw := range map[string][]byte{"original-approval.private.json": managed.approval, "original-bundle.private.json": bundle, "trusted-root.private.json": trustedRoot, "catalogue1.private.json": managed.catalogue, "catalogue2.private.json": cat2} {
		d11Write(t, filepath.Join(endpoint, name), raw)
	}
	d11JSON(t, filepath.Join(endpoint, "anchor.json"), managed.anchor)
	for _, name := range []string{"api-ca.pem", "api-cert.pem", "api-key.private.pem", "registry-ca.pem"} {
		d11Write(t, filepath.Join(endpoint, name), d11Read(t, filepath.Join(root, name), 256<<10))
	}
	store, err := truststate.Create(context.Background(), filepath.Join(endpoint, "trust"), managed.anchor, managed.catalogue)
	stateRequire(t, err == nil && store.Close() == nil)
	audit, err := evidence.Open(filepath.Join(endpoint, "data", "evidence"))
	stateRequire(t, err == nil && audit.Close() == nil)
	info := d11Material{Kind: kind, SourceCommit: commit, LocalImageID: image, ManifestSHA256: hashed(manifest), ConfigSHA256: hashed(config), LayerSHA256s: []string{}, DiffIDs: diffs, Catalogue1SHA256: hashed(managed.catalogue), Catalogue2SHA256: hashed(cat2), StoreID: managed.anchor.StoreID, Policies: []d11Policy{policy}, Anchor: managed.anchor}
	for _, layer := range layers {
		info.LayerSHA256s = append(info.LayerSHA256s, hashed(layer))
	}
	report := stateNew(info, lane, scenario, "prepare")
	scope := report.ConfiguredScope
	management := scope
	management.ObjectType, management.ObjectID = "control-plane", "d12-state-management"
	token, tokenHash, err := authn.GenerateToken(32)
	stateRequire(t, err == nil)
	d11Write(t, filepath.Join(endpoint, "admin-token.private"), []byte(token))
	d11JSON(t, filepath.Join(endpoint, "identities.json"), authn.File{Version: authn.FileVersion, Identities: []authn.Identity{{TokenID: "d12-state-admin-token", TokenHash: tokenHash, Principal: authz.Principal{ID: stateActor, TenantID: scope.TenantID, Roles: []authz.Role{authz.RoleAdmin}, AllowedScopes: []authz.ResourceScope{scope, management}}}}})
	common := map[string]any{"addr": "127.0.0.1:" + statePort(kind), "identitiesFile": filepath.Join(endpoint, "identities.json"), "tlsCertFile": filepath.Join(endpoint, "api-cert.pem"), "tlsKeyFile": filepath.Join(endpoint, "api-key.private.pem"), "tenantId": scope.TenantID, "siteId": scope.SiteID, "environment": "candidate"}
	trustConfig := map[string]any{}
	for key, value := range common {
		trustConfig[key] = value
	}
	trustConfig["storePath"], trustConfig["anchorFile"] = filepath.Join(endpoint, "trust"), filepath.Join(endpoint, "anchor.json")
	trustConfig["auditDir"], trustConfig["registryCAFile"] = filepath.Join(endpoint, "data", "evidence"), filepath.Join(endpoint, "registry-ca.pem")
	trustConfig["writesEnabled"], trustConfig["webDir"] = true, "/app/web"
	d11JSON(t, filepath.Join(endpoint, "trust-config.json"), trustConfig)
	common["dataDir"], common["managementObjectId"] = filepath.Join(endpoint, "data"), management.ObjectID
	d11JSON(t, filepath.Join(endpoint, "product-config.json"), common)
	d11JSON(t, filepath.Join(endpoint, "materials.private.json"), info)
	report.Offline = stateInspect(t, endpoint, info, false)
	stateRequire(t, report.Offline.Inspection.Sequence == 1 && report.Offline.Inspection.LedgerUsed == 0 && len(report.Offline.Journal) == 0 && len(report.Offline.AuditEvents) == 0)
	stateSave(t, root, report)
}

func stateInfo(t *testing.T, root, lane, scenario, kind, commit, image string) d11Material {
	t.Helper()
	endpoint := stateEndpoint(root, lane, scenario, kind)
	d11Dir(t, endpoint)
	var info d11Material
	d11Decode(t, d11Read(t, filepath.Join(endpoint, "materials.private.json"), 256<<10), &info)
	d11Decode(t, d11Read(t, filepath.Join(endpoint, "anchor.json"), 8<<10), &info.Anchor)
	stateRequire(t, info.Kind == kind && info.SourceCommit == commit && info.LocalImageID == image && info.ConfigSHA256 == image && len(info.Policies) == 1 && reflect.DeepEqual(info.LayerSHA256s, info.DiffIDs) && info.StoreID == info.Anchor.StoreID && info.Catalogue1SHA256 == info.Anchor.InitialSHA256)
	stateRequire(t, info.Policies[0].Name == "original" && info.Policies[0].PolicyID == "d12-state-"+lane && info.Policies[0].BundleArtifactSHA256 == info.ManifestSHA256)
	for name, want := range map[string]string{"catalogue1.private.json": info.Catalogue1SHA256, "catalogue2.private.json": info.Catalogue2SHA256, "original-approval.private.json": info.Policies[0].ApprovalEnvelopeSHA256, "original-bundle.private.json": info.Policies[0].BundleSHA256, "trusted-root.private.json": info.Policies[0].TrustedRootSHA256} {
		stateRequire(t, hashed(d11Read(t, filepath.Join(endpoint, name), 1<<20)) == want)
	}
	return info
}

func stateRaw(t *testing.T, name string, limit int64, empty bool) []byte {
	t.Helper()
	fd, err := unix.Open(name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	stateRequire(t, err == nil)
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var before, after unix.Stat_t
	stateRequire(t, unix.Fstat(fd, &before) == nil && before.Mode&unix.S_IFMT == unix.S_IFREG && before.Mode&07777 == 0600 && before.Uid == 10001 && before.Gid == 10001 && before.Nlink == 1 && before.Size >= 0 && before.Size <= limit && (empty || before.Size > 0))
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	stateRequire(t, err == nil && len(raw) <= int(limit) && int64(len(raw)) == before.Size && unix.Fstat(fd, &after) == nil && before.Dev == after.Dev && before.Ino == after.Ino && before.Size == after.Size && before.Mtim == after.Mtim && before.Ctim == after.Ctim)
	return raw
}
func stateHash(raw []byte) stateRawHash {
	return stateRawHash{Bytes: len(raw), SHA256: strings.TrimPrefix(hashed(raw), "sha256:")}
}
func stateAuditRaw(t *testing.T, endpoint string) ([]byte, []byte) {
	t.Helper()
	directory := filepath.Join(endpoint, "data", "evidence")
	d11Dir(t, directory)
	return stateRaw(t, filepath.Join(directory, "events.jsonl"), 4<<20, true), stateRaw(t, filepath.Join(directory, "checkpoint.json"), 4096, false)
}
func stateRecordHash(t *testing.T, endpoint string) string {
	t.Helper()
	path := filepath.Join(endpoint, "trust", "trust.db")
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	stateRequire(t, err == nil)
	defer unix.Close(fd)
	var before, after unix.Stat_t
	stateRequire(t, unix.Fstat(fd, &before) == nil && before.Mode&unix.S_IFMT == unix.S_IFREG && before.Mode&07777 == 0600 && before.Uid == 10001 && before.Gid == 10001 && before.Nlink == 1 && before.Size > 0 && before.Size <= 64<<20)
	// A held, validated FD is the only path supplied to this read-only bbolt
	// handle. No raw record or ledger ticket token is ever exported.
	db, err := bolt.Open(fmt.Sprintf("/proc/self/fd/%d", fd), 0600, &bolt.Options{ReadOnly: true, Timeout: time.Second})
	stateRequire(t, err == nil)
	var digest string
	err = db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("trusted-state-v1"))
		if bucket == nil {
			return errors.New("fixture record missing")
		}
		raw := bucket.Get([]byte("state"))
		if len(raw) == 0 || len(raw) > 8<<20 {
			return errors.New("fixture record rejected")
		}
		digest = strings.TrimPrefix(hashed(raw), "sha256:")
		return nil
	})
	stateRequire(t, err == nil && db.Close() == nil && unix.Fstat(fd, &after) == nil && before.Dev == after.Dev && before.Ino == after.Ino && before.Size == after.Size && before.Mtim == after.Mtim && before.Ctim == after.Ctim)
	return digest
}
func stateInspect(t *testing.T, endpoint string, info d11Material, badCheckpoint bool) *stateOffline {
	t.Helper()
	beforeLog, beforeCheckpoint := stateAuditRaw(t, endpoint)
	store, err := truststate.Open(context.Background(), filepath.Join(endpoint, "trust"), info.Anchor)
	stateRequire(t, err == nil)
	inspection, err := store.Inspect(context.Background())
	stateRequire(t, err == nil)
	journal, err := store.Journal(context.Background())
	stateRequire(t, err == nil && store.Close() == nil)
	result := &stateOffline{TrustRecordSHA256: stateRecordHash(t, endpoint), Inspection: inspection, Journal: journal, AuditOpen: "verified", AuditEvents: []evidence.EvidenceEvent{}, AuditBindings: []stateAuditBinding{}, AuditLog: stateHash(beforeLog), Checkpoint: stateHash(beforeCheckpoint)}
	stateRequire(t, inspection.Authorization == "BLOCKED" && inspection.CatalogueValid && inspection.Catalogue.StoreID == info.StoreID)
	if journal == nil {
		result.Journal = []truststate.JournalEntry{}
	}
	if len(beforeLog) > 0 {
		stateRequire(t, beforeLog[len(beforeLog)-1] == '\n')
		for _, line := range bytes.Split(beforeLog[:len(beforeLog)-1], []byte{'\n'}) {
			stateRequire(t, len(line) > 0)
			var event evidence.EvidenceEvent
			d11Decode(t, line, &event)
			result.AuditEvents = append(result.AuditEvents, event)
		}
	}
	audit, err := evidence.Open(filepath.Join(endpoint, "data", "evidence"))
	if badCheckpoint {
		stateRequire(t, bytes.Equal(beforeCheckpoint, []byte("{}\n")) && err != nil && audit == nil)
		result.AuditOpen = "rejected-checkpoint"
	} else {
		stateRequire(t, err == nil)
		proof, verifyErr := audit.Verify()
		stateRequire(t, verifyErr == nil && proof.Valid && proof.Count == proof.ExpectedCount && proof.LastHash == proof.ExpectedLastHash && proof.Count == uint64(len(result.AuditEvents)))
		result.Audit = &proof
		stateRequire(t, audit.Close() == nil)
	}
	events := map[string]evidence.EvidenceEvent{}
	for _, event := range result.AuditEvents {
		if event.IdempotencyKey != "" {
			_, exists := events[event.IdempotencyKey]
			stateRequire(t, !exists)
			events[event.IdempotencyKey] = event
		}
	}
	for _, entry := range journal {
		binding := stateAuditBinding{OperationID: entry.Operation.ID}
		if event, ok := events["image-trust/"+entry.Operation.ID+"/prepared"]; ok {
			copy := event
			binding.Prepared = &copy
		}
		if event, ok := events["image-trust/"+entry.Operation.ID+"/result"]; ok {
			copy := event
			binding.Result = &copy
		}
		result.AuditBindings = append(result.AuditBindings, binding)
	}
	afterLog, afterCheckpoint := stateAuditRaw(t, endpoint)
	stateRequire(t, bytes.Equal(beforeLog, afterLog) && bytes.Equal(beforeCheckpoint, afterCheckpoint))
	return result
}

func stateSDKLoad(t *testing.T, endpoint string, info d11Material) *stateSDK {
	t.Helper()
	path := filepath.Join(endpoint, "sdk.private.json")
	_, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	stateRequire(t, err == nil)
	var sdk stateSDK
	d11Decode(t, d11Read(t, path, 32<<10), &sdk)
	stateSDKCheck(t, sdk, info)
	return &sdk
}
func stateSDKCheck(t *testing.T, sdk stateSDK, info d11Material) {
	t.Helper()
	p := sdk.Projection
	policy := info.Policies[0]
	stateRequire(t, sdk.Boundary == binding.ManagedBoundary && sdk.Authorization == "BLOCKED" && sdk.Verified && sdk.PolicyID == policy.PolicyID && sdk.PolicyRevision == 1 && sdk.EvidenceSHA256 == hashed(encode(t, p)))
	stateRequire(t, p.Schema == "chengwang.managed-binding-evidence/v1" && p.Grant == policy.GrantID && p.Catalogue == info.Catalogue1SHA256 && p.Generation == 1 && p.Reference == d11Repository+"@"+info.ManifestSHA256 && p.Approval == policy.ApprovalSHA256 && p.Manifest == info.ManifestSHA256 && p.Config == info.ConfigSHA256 && p.Bundle == policy.BundleSHA256 && p.Root == policy.TrustedRootSHA256 && p.ObservedAtUnixNano > 0 && p.ValidUntilUnix > p.ObservedAtUnixNano/int64(time.Second) && regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(p.Graph))
}
func stateDomain(t *testing.T, endpoint, lane string, info d11Material, store *truststate.Store, opID string) *stateSDK {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if lane == "update" {
		stateRequire(t, store.UpdateTracked(ctx, d11Read(t, filepath.Join(endpoint, "catalogue2.private.json"), 1<<20), opID) == nil)
		return nil
	}
	approval := d11Read(t, filepath.Join(endpoint, "original-approval.private.json"), 64<<10)
	if lane == "verify-reserved" {
		_, err := store.BeginTracked(ctx, info.Policies[0].PolicyID, approval, opID, nil)
		stateRequire(t, err == nil)
		return nil
	}
	roots := x509.NewCertPool()
	stateRequire(t, roots.AppendCertsFromPEM(d11Read(t, filepath.Join(endpoint, "registry-ca.pem"), 256<<10)))
	managed, err := binding.ManagedBindTracked(ctx, store, opID, info.Policies[0].PolicyID, approval, d11Read(t, filepath.Join(endpoint, "original-bundle.private.json"), 1<<20), d11Read(t, filepath.Join(endpoint, "trusted-root.private.json"), 1<<20), roots, "", nil)
	stateRequire(t, err == nil && managed.Verified())
	b := managed.Binding()
	stateRequire(t, b.Verified() && b.Boundary() == binding.Boundary && b.Authorization() == "BLOCKED")
	projection := stateSDKProjection{"chengwang.managed-binding-evidence/v1", managed.GrantID(), managed.CatalogueSHA256(), managed.CatalogueGeneration(), b.Reference(), b.ApprovalSHA256(), b.ManifestSHA256(), b.ConfigSHA256(), b.GraphSHA256(), b.BundleSHA256(), b.TrustedRootSHA256(), b.ObservedAt().UnixNano(), managed.ValidUntilUnix()}
	sdk := stateSDK{Boundary: managed.Boundary(), Authorization: managed.Authorization(), Verified: managed.Verified(), PolicyID: b.PolicyID(), PolicyRevision: b.PolicyRevision(), EvidenceSHA256: managed.EvidenceSHA256(), Projection: projection}
	stateSDKCheck(t, sdk, info)
	d11JSON(t, filepath.Join(endpoint, "sdk.private.json"), sdk)
	return &sdk
}

func stateOperationData(info d11Material, lane string) map[string]string {
	if lane == "update" {
		return map[string]string{"catalogueSHA256": info.Catalogue2SHA256}
	}
	p := info.Policies[0]
	return map[string]string{"policyId": p.PolicyID, "approvalSHA256": p.ApprovalEnvelopeSHA256, "bundleSHA256": p.BundleSHA256, "rootSHA256": p.TrustedRootSHA256}
}
func statePrepareOperation(t *testing.T, store *truststate.Store, audit *evidence.Store, info d11Material, lane string, wrongPrefix bool) truststate.Operation {
	t.Helper()
	proof, err := audit.Verify()
	stateRequire(t, err == nil && proof.Valid)
	kind := "verify"
	if lane == "update" {
		kind = "update"
	}
	op := truststate.Operation{ID: randomManagedID(t), ActorID: stateActor, ScopeSHA256: hashed(encode(t, stateScope(info.StoreID))), Kind: kind, Data: stateOperationData(info, lane), AuditBaseCount: proof.Count, AuditBaseHash: proof.LastHash}
	if wrongPrefix {
		stateRequire(t, proof.Count == 1 && proof.LastHash != strings.Repeat("1", 64))
		op.AuditBaseHash = strings.Repeat("1", 64)
	}
	stateRequire(t, store.PrepareOperation(context.Background(), op) == nil)
	return op
}
func stateAppend(t *testing.T, audit *evidence.Store, info d11Material, op truststate.Operation, result string, data map[string]string, foreign bool) evidence.EvidenceEvent {
	t.Helper()
	actor := stateActor
	if foreign {
		actor = stateForeignActor
	}
	phase := "result"
	if result == "prepared" {
		phase = "prepared"
	}
	event, created, err := audit.AppendOnce(evidence.EvidenceEvent{TraceID: op.ID, ActorID: actor, Action: "image_trust." + op.Kind, Target: "image-trust/" + info.StoreID, Result: result, Data: data}, "image-trust/"+op.ID+"/"+phase)
	stateRequire(t, err == nil && created && event.ActorID == actor && event.Result == result)
	return event
}
func stateLast(t *testing.T, store *truststate.Store, id string) truststate.JournalEntry {
	t.Helper()
	journal, err := store.Journal(context.Background())
	stateRequire(t, err == nil && len(journal) > 0)
	entry := journal[len(journal)-1]
	stateRequire(t, entry.Operation.ID == id)
	return entry
}
func stateSeal(t *testing.T, store *truststate.Store, opID, lane string) truststate.JournalEntry {
	t.Helper()
	if lane == "verify-reserved" {
		stateRequire(t, store.FinishOperation(context.Background(), opID, truststate.OutcomeVerificationReserved, map[string]string{}) == nil)
	}
	entry := stateLast(t, store, opID)
	stateRequire(t, entry.Outcome != "" && !entry.Acknowledged)
	return entry
}
func stateResultLabel(lane string) string {
	if lane == "update" {
		return "completed"
	}
	if lane == "verify-reserved" {
		return "rejected"
	}
	return "verification_consumed"
}
func stateSyncDir(t *testing.T, path string) {
	t.Helper()
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	stateRequire(t, err == nil)
	stateRequire(t, unix.Fsync(fd) == nil)
	stateRequire(t, unix.Close(fd) == nil)
}
func stateSeed(t *testing.T, root, lane, scenario string, info d11Material) {
	t.Helper()
	prior := stateLoad(t, root, lane, scenario, info.Kind, "prepare")
	stateRequire(t, prior.Offline != nil && prior.Offline.Inspection.Sequence == 1 && reflect.DeepEqual(encode(t, prior.d11Material), encode(t, info)))
	endpoint := stateEndpoint(root, lane, scenario, info.Kind)
	d11Write(t, filepath.Join(endpoint, "intent-seed.private"), []byte("single-public-transaction-seed\n"))
	store, err := truststate.Open(context.Background(), filepath.Join(endpoint, "trust"), info.Anchor)
	stateRequire(t, err == nil)
	defer store.Close()
	audit, err := evidence.Open(filepath.Join(endpoint, "data", "evidence"))
	stateRequire(t, err == nil)
	defer audit.Close()
	if scenario == "wrong-prefix" {
		event, created, appendErr := audit.AppendOnce(evidence.EvidenceEvent{TraceID: "d12-state-base", ActorID: stateActor, Action: "image_trust.read", Target: "image-trust/" + info.StoreID, Result: "observed"}, "state-matrix/base")
		stateRequire(t, appendErr == nil && created && event.PreviousHash == strings.Repeat("0", 64))
	}
	if scenario == "later-invalid-acked" {
		statePrepareOperation(t, store, audit, info, lane, false)
	}
	op := statePrepareOperation(t, store, audit, info, lane, scenario == "wrong-prefix")
	index := stateIndex(stateBoundaries, scenario)
	healthy := index >= 0
	var sdk *stateSDK
	if !healthy || index >= 1 {
		prepared := stateAppend(t, audit, info, op, "prepared", op.Data, scenario == "prepared-key-conflict" || scenario == "later-invalid-acked")
		if !healthy || index >= 2 {
			stateRequire(t, store.BindPreparedAudit(context.Background(), op.ID, prepared.Hash) == nil)
			sdk = stateDomain(t, endpoint, lane, info, store, op.ID)
			if !healthy || index >= 3 {
				entry := stateSeal(t, store, op.ID, lane)
				if (!healthy && scenario != "prepared-audit-missing") || (healthy && index >= 4) {
					result := stateAppend(t, audit, info, op, stateResultLabel(lane), entry.OutcomeData, scenario == "result-key-conflict")
					if (!healthy && scenario != "result-key-conflict") || (healthy && index >= 5) {
						stateRequire(t, store.AcknowledgeOperation(context.Background(), op.ID, result.Hash) == nil)
					}
				}
			}
		}
	}
	stateRequire(t, store.Close() == nil && audit.Close() == nil)
	if scenario == "acked-audit-missing" || scenario == "prepared-audit-missing" {
		data := filepath.Join(endpoint, "data")
		auditDir := filepath.Join(data, "evidence")
		stateRequire(t, os.Rename(auditDir, filepath.Join(data, "evidence.original.private")) == nil)
		stateSyncDir(t, data)
		fresh, openErr := evidence.Open(auditDir)
		stateRequire(t, openErr == nil && fresh.Close() == nil)
		stateSyncDir(t, data)
	}
	if scenario == "bad-checkpoint" {
		// Deliberate, explicitly scoped corruption is applied only after the
		// healthy audit has closed. Offline sampling never repairs these bytes.
		temporary := filepath.Join(endpoint, "bad-checkpoint.private.next")
		d11Write(t, temporary, []byte("{}\n"))
		stateRequire(t, os.Rename(temporary, filepath.Join(endpoint, "data", "evidence", "checkpoint.json")) == nil)
		stateSyncDir(t, filepath.Join(endpoint, "data", "evidence"))
		stateSyncDir(t, endpoint)
	}
	report := stateNew(info, lane, scenario, "seed")
	report.Offline = stateInspect(t, endpoint, info, scenario == "bad-checkpoint")
	report.SDK = sdk
	stateRequire(t, reflect.DeepEqual(sdk, stateSDKLoad(t, endpoint, info)))
	stateCheckSeed(t, report)
	stateSave(t, root, report)
}

func stateCheckSeed(t *testing.T, report stateReport) {
	t.Helper()
	o := report.Offline
	stateRequire(t, o != nil)
	index := stateIndex(stateBoundaries, report.Scenario)
	seq, audits, ledger, generation := uint64(2), 0, 0, uint64(1)
	ack := false
	state, outcome := "PREPARED", ""
	if index >= 0 {
		if index >= 1 {
			audits = 1
		}
		if index >= 2 {
			seq = 4
			if report.Lane == "update" {
				generation, state, outcome = 2, "COMMITTED", truststate.OutcomeCatalogueCommitted
			} else {
				ledger, state = 1, "RESERVED"
				if report.Lane == "verify-consumed" {
					seq, state, outcome = 5, "CONSUMED", truststate.OutcomeVerificationConsumed
				}
			}
		}
		if index >= 3 && report.Lane == "verify-reserved" {
			seq, outcome = 5, truststate.OutcomeVerificationReserved
		}
		if index >= 4 {
			audits = 2
		}
		if index >= 5 {
			seq++
			ack = true
		}
	} else {
		seq, audits, ack = 5, 2, true
		if report.Lane == "update" {
			generation, state, outcome = 2, "COMMITTED", truststate.OutcomeCatalogueCommitted
		} else {
			seq, ledger, state, outcome = 6, 1, "RESERVED", truststate.OutcomeVerificationReserved
			if report.Lane == "verify-consumed" {
				state, outcome = "CONSUMED", truststate.OutcomeVerificationConsumed
			}
		}
		switch report.Scenario {
		case "acked-audit-missing":
			audits = 0
		case "prepared-audit-missing":
			seq--
			audits = 0
			ack = false
		case "wrong-prefix":
			audits = 3
		case "result-key-conflict":
			seq--
			ack = false
		case "later-invalid-acked":
			seq++
		}
	}
	journalCount := 1
	if report.Scenario == "later-invalid-acked" {
		journalCount = 2
	}
	stateRequire(t, o.Inspection.Sequence == seq && o.Inspection.LedgerUsed == ledger && o.Inspection.Catalogue.Generation == generation && len(o.Journal) == journalCount && len(o.AuditEvents) == audits)
	entry := o.Journal[len(o.Journal)-1]
	stateRequire(t, entry.State == state && entry.Outcome == outcome && entry.Acknowledged == ack && entry.Operation.ActorID == stateActor && entry.Operation.ScopeSHA256 == hashed(encode(t, report.CanonicalScope)) && d11SameData(entry.Operation.Data, stateOperationData(report.d11Material, report.Lane)))
	stateRequire(t, (index < 0 || index >= 2) == (entry.Operation.PreparedAuditHash != ""))
	stateRequire(t, (report.SDK != nil) == (report.Lane == "verify-consumed" && (index < 0 || index >= 2)))
	if report.SDK != nil {
		stateRequire(t, len(o.Inspection.Consumptions) == 1 && o.Inspection.Consumptions[0].EvidenceSHA256 == report.SDK.EvidenceSHA256 && entry.EvidenceSHA256 == report.SDK.EvidenceSHA256)
	}
	if journalCount == 2 {
		first := o.Journal[0]
		stateRequire(t, first.State == "PREPARED" && first.Outcome == "" && !first.Acknowledged && first.Operation.PreparedAuditHash == "" && first.ResultAuditHash == "" && first.Operation.ActorID == stateActor && first.Operation.ScopeSHA256 == entry.Operation.ScopeSHA256 && d11SameData(first.Operation.Data, entry.Operation.Data))
	}
}

func stateFinal(lane, scenario string) (sequence, generation uint64, ledger int, state, outcome, label string) {
	index := stateIndex(stateBoundaries, scenario)
	if index < 2 {
		return 5, 1, 0, "PREPARED", truststate.OutcomeInterrupted, "interrupted"
	}
	if lane == "update" {
		return 5, 2, 0, "COMMITTED", truststate.OutcomeCatalogueCommitted, "completed"
	}
	if lane == "verify-reserved" {
		return 6, 1, 1, "RESERVED", truststate.OutcomeVerificationReserved, "rejected"
	}
	return 6, 1, 1, "CONSUMED", truststate.OutcomeVerificationConsumed, "verification_consumed"
}
func stateClient(t *testing.T, root, kind string) *http.Client {
	t.Helper()
	roots := x509.NewCertPool()
	stateRequire(t, roots.AppendCertsFromPEM(d11Read(t, filepath.Join(root, "api-ca.pem"), 256<<10)))
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, ForceAttemptHTTP2: false,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: "api.fixture.invalid", NextProtos: []string{"http/1.1"}},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != net.JoinHostPort("api.fixture.invalid", statePort(kind)) {
				return nil, errors.New("fixture destination rejected")
			}
			return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", statePort(kind)))
		}}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
func stateGet(t *testing.T, ctx context.Context, client *http.Client, target, token string, destination any) bool {
	t.Helper()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	stateRequire(t, err == nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := client.Do(request)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, (4<<20)+1))
	if err != nil || response.StatusCode == 409 || response.StatusCode == 503 {
		return false
	}
	stateRequire(t, response.StatusCode == 200 && len(raw) <= 4<<20)
	d11Decode(t, raw, destination)
	return true
}
func stateSnapshot(t *testing.T, root, lane, scenario string, info d11Material) (imagetrust.Status, imagetrust.History) {
	t.Helper()
	endpoint := stateEndpoint(root, lane, scenario, info.Kind)
	token := string(d11Read(t, filepath.Join(endpoint, "admin-token.private"), 512))
	client := stateClient(t, root, info.Kind)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	api := "https://api.fixture.invalid:" + statePort(info.Kind)
	for ctx.Err() == nil {
		var status imagetrust.Status
		var history imagetrust.History
		if stateGet(t, ctx, client, api+"/api/v1/image-trust", token, &status) && stateGet(t, ctx, client, api+"/api/v1/image-trust/history?limit=50", token, &history) {
			ack := true
			for _, entry := range history.Entries {
				ack = ack && entry.Acknowledged && len(entry.PreparedAuditHash) == 64 && len(entry.ResultAuditHash) == 64
			}
			if status.Sequence == history.Sequence && history.Total == len(history.Entries) && ack {
				return status, history
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	stateRequire(t, false)
	return imagetrust.Status{}, imagetrust.History{}
}
func stateCheckStatus(t *testing.T, status imagetrust.Status, history imagetrust.History, lane, scenario, action string, info d11Material) {
	t.Helper()
	sequence, generation, ledger, state, outcome, _ := stateFinal(lane, scenario)
	cat := info.Catalogue1SHA256
	if generation == 2 {
		cat = info.Catalogue2SHA256
	}
	recovery := 1
	if action == "second-read" || scenario == "after-journal-ack" {
		recovery = 0
	}
	stateRequire(t, status.Boundary == imagetrust.StatusBoundary && status.Authorization == "BLOCKED" && !status.DeviceActionsExecuted && status.Healthy && status.Fresh && !status.RefreshRequired && !status.RefreshFresh && status.RefreshLastSuccessUnix == 0 && status.RefreshUntilUnix == 0)
	stateRequire(t, status.StoreID == info.StoreID && status.Sequence == sequence && status.Generation == generation && status.CatalogueSHA256 == cat && status.NotAfterUnix > time.Now().Unix() && status.LedgerEntries == ledger && status.LedgerCapacity == 4096 && status.RecoveryCompleted == recovery && status.RevokedKeys == 0 && status.RevokedApprovals == 0 && status.RevokedManifests == 0)
	reserved, consumed := 0, 0
	if state == "RESERVED" {
		reserved = 1
	}
	if state == "CONSUMED" {
		consumed = 1
	}
	policyState := state
	if ledger == 0 {
		policyState = "AVAILABLE"
	}
	stateRequire(t, status.Reserved == reserved && status.Consumed == consumed && len(status.Policies) == 1 && status.Policies[0].State == policyState && status.Policies[0].PolicyID == info.Policies[0].PolicyID && status.Policies[0].GrantID == info.Policies[0].GrantID && status.Policies[0].Revision == 1 && status.Policies[0].ManifestSHA256 == info.ManifestSHA256)
	stateRequire(t, history.Boundary == imagetrust.HistoryBoundary && history.Authorization == "BLOCKED" && !history.DeviceActionsExecuted && history.Sequence == sequence && history.Total == 1 && len(history.Entries) == 1 && history.Offset == 0)
	h := history.Entries[0]
	kind := "verify"
	if lane == "update" {
		kind = "update"
	}
	stateRequire(t, h.ActorID == stateActor && h.Kind == kind && h.State == state && h.Outcome == outcome && h.Acknowledged && h.PreparedAtUnix > 0 && h.ResultAtUnix >= h.PreparedAtUnix)
}
func stateObserve(t *testing.T, root, lane, scenario, action string, info d11Material) {
	t.Helper()
	stateRequire(t, stateIndex(stateBoundaries, scenario) >= 0)
	previous := "seed"
	if action == "second-read" {
		previous = "reopen-first"
	}
	prior := stateLoad(t, root, lane, scenario, info.Kind, previous)
	stateRequire(t, prior.Offline != nil && bytes.Equal(encode(t, prior.d11Material), encode(t, info)))
	status, history := stateSnapshot(t, root, lane, scenario, info)
	stateCheckStatus(t, status, history, lane, scenario, action, info)
	stateRequire(t, len(prior.Offline.Journal) == 1 && history.Entries[0].OperationID == prior.Offline.Journal[0].Operation.ID)
	logRaw, cpRaw := stateAuditRaw(t, stateEndpoint(root, lane, scenario, info.Kind))
	logHash, cpHash := stateHash(logRaw), stateHash(cpRaw)
	report := stateNew(info, lane, scenario, action)
	report.Status, report.History, report.AuditLog, report.Checkpoint = &status, &history, &logHash, &cpHash
	report.SDK = stateSDKLoad(t, stateEndpoint(root, lane, scenario, info.Kind), info)
	stateRequire(t, reflect.DeepEqual(prior.SDK, report.SDK))
	if action == "second-read" {
		first := stateLoad(t, root, lane, scenario, info.Kind, "first-read")
		stateRequire(t, first.History != nil && reflect.DeepEqual(first.History.Entries, history.Entries) && prior.Offline.AuditLog == logHash && prior.Offline.Checkpoint == cpHash && first.AuditLog != nil && first.Checkpoint != nil && *first.AuditLog == logHash && *first.Checkpoint == cpHash)
	}
	stateSave(t, root, report)
}
func stateCheckRecovered(t *testing.T, report, seed stateReport) {
	t.Helper()
	o := report.Offline
	stateRequire(t, o != nil && seed.Offline != nil)
	sequence, generation, ledger, state, outcome, label := stateFinal(report.Lane, report.Scenario)
	cat := report.Catalogue1SHA256
	if generation == 2 {
		cat = report.Catalogue2SHA256
	}
	stateRequire(t, o.Inspection.Sequence == sequence && o.Inspection.Catalogue.Generation == generation && o.Inspection.Catalogue.SHA256 == cat && o.Inspection.LedgerUsed == ledger && len(o.Journal) == 1 && len(o.AuditEvents) == 2 && len(o.AuditBindings) == 1 && o.Audit != nil && o.Audit.Count == 2)
	entry := o.Journal[0]
	original := seed.Offline.Journal[0]
	stateRequire(t, entry.Operation.ID == original.Operation.ID && entry.Operation.ActorID == stateActor && entry.Operation.ScopeSHA256 == hashed(encode(t, report.CanonicalScope)) && entry.Operation.Kind == original.Operation.Kind && d11SameData(entry.Operation.Data, original.Operation.Data) && entry.Operation.AuditBaseCount == 0 && entry.Operation.AuditBaseHash == strings.Repeat("0", 64))
	stateRequire(t, entry.State == state && entry.Outcome == outcome && entry.Acknowledged)
	b := o.AuditBindings[0]
	stateRequire(t, b.OperationID == entry.Operation.ID && b.Prepared != nil && b.Result != nil)
	stateRequire(t, b.Prepared.Hash == entry.Operation.PreparedAuditHash && b.Result.Hash == entry.ResultAuditHash && b.Prepared.Result == "prepared" && b.Result.Result == label && d11SameData(b.Prepared.Data, entry.Operation.Data) && d11SameData(b.Result.Data, entry.OutcomeData))
	for _, event := range []*evidence.EvidenceEvent{b.Prepared, b.Result} {
		stateRequire(t, event.TraceID == entry.Operation.ID && event.ActorID == stateActor && event.Action == "image_trust."+entry.Operation.Kind && event.Target == "image-trust/"+report.StoreID)
	}
	stateRequire(t, reflect.DeepEqual(seed.SDK, report.SDK) && reflect.DeepEqual(seed.Offline.Inspection.Consumptions, o.Inspection.Consumptions))
	if report.SDK != nil {
		stateRequire(t, entry.EvidenceSHA256 == report.SDK.EvidenceSHA256 && len(o.Inspection.Consumptions) == 1 && o.Inspection.Consumptions[0].EvidenceSHA256 == report.SDK.EvidenceSHA256)
	}
}
func stateSameOffline(t *testing.T, a, b *stateOffline) {
	t.Helper()
	stateRequire(t, a != nil && b != nil && a.TrustRecordSHA256 == b.TrustRecordSHA256 && reflect.DeepEqual(a.Inspection, b.Inspection) && reflect.DeepEqual(a.Journal, b.Journal) && a.AuditOpen == b.AuditOpen && reflect.DeepEqual(a.AuditEvents, b.AuditEvents) && reflect.DeepEqual(a.AuditBindings, b.AuditBindings) && a.AuditLog == b.AuditLog && a.Checkpoint == b.Checkpoint)
	// VerifyReport.VerifiedAt is a new actual observation, not durable content.
	if a.Audit == nil || b.Audit == nil {
		stateRequire(t, a.Audit == nil && b.Audit == nil)
	} else {
		left, right := *a.Audit, *b.Audit
		left.VerifiedAt = time.Time{}
		right.VerifiedAt = time.Time{}
		stateRequire(t, reflect.DeepEqual(left, right))
	}
}
func stateReopen(t *testing.T, root, lane, scenario, action string, info d11Material) {
	t.Helper()
	seed := stateLoad(t, root, lane, scenario, info.Kind, "seed")
	stateRequire(t, seed.Offline != nil && bytes.Equal(encode(t, seed.d11Material), encode(t, info)))
	endpoint := stateEndpoint(root, lane, scenario, info.Kind)
	report := stateNew(info, lane, scenario, action)
	report.Offline = stateInspect(t, endpoint, info, scenario == "bad-checkpoint")
	report.SDK = stateSDKLoad(t, endpoint, info)
	stateRequire(t, reflect.DeepEqual(seed.SDK, report.SDK))
	if report.CaseKind == "rejected" {
		stateSameOffline(t, seed.Offline, report.Offline)
	} else {
		stateCheckRecovered(t, report, seed)
		readAction := "first-read"
		if action == "reopen-second" {
			readAction = "second-read"
		}
		read := stateLoad(t, root, lane, scenario, info.Kind, readAction)
		stateRequire(t, read.Status != nil && read.History != nil && read.AuditLog != nil && read.Checkpoint != nil && read.Status.Sequence == report.Offline.Inspection.Sequence && read.Status.LedgerEntries == report.Offline.Inspection.LedgerUsed && read.History.Total == len(report.Offline.Journal) && *read.AuditLog == report.Offline.AuditLog && *read.Checkpoint == report.Offline.Checkpoint && reflect.DeepEqual(read.SDK, report.SDK))
		h, entry := read.History.Entries[0], report.Offline.Journal[0]
		stateRequire(t, h.OperationID == entry.Operation.ID && h.ActorID == entry.Operation.ActorID && h.Kind == entry.Operation.Kind && h.State == entry.State && h.Outcome == entry.Outcome && h.Acknowledged == entry.Acknowledged && h.PreparedAuditHash == entry.Operation.PreparedAuditHash && h.ResultAuditHash == entry.ResultAuditHash && h.GrantID == entry.GrantID && h.Generation == entry.Generation && h.CatalogueSHA256 == entry.CatalogueSHA256)
	}
	if action == "reopen-second" {
		prior := stateLoad(t, root, lane, scenario, info.Kind, "reopen-first")
		stateSameOffline(t, prior.Offline, report.Offline)
		stateRequire(t, reflect.DeepEqual(prior.SDK, report.SDK))
	}
	stateSave(t, root, report)
}
