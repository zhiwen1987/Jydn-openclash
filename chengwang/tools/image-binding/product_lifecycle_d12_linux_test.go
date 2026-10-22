//go:build linux && productregistry && productlifecycle

package binding_test

// This tagged driver provisions isolated test material and calls the actual
// image entrypoint over normal TLS. It never composes a product backend, calls
// ConfirmRefresh, or sends the catalogue PUT route. Source and Registry access
// counts come from the independently observed fixture processes, not this file.
import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	verifier "chengwang-image-verifier"
	"chengwang/image-binding/trustcatalog"
	"chengwang/image-binding/truststate"
	"chengwang/internal/authn"
	"chengwang/internal/authz"
	"chengwang/internal/evidence"
	"chengwang/internal/imagetrust"
	"golang.org/x/sys/unix"
)

const d12FeedURL = "https://feed.fixture.invalid:5444/feed"

type d12Material struct {
	d11Material
	FeedURL                string `json:"feedURL"`
	FeedSPKI               string `json:"feedSPKI"`
	FeedCASHA256           string `json:"feedCASHA256"`
	RefreshIntervalSeconds int    `json:"refreshIntervalSeconds"`
	RefreshMaxAgeSeconds   int    `json:"refreshMaxAgeSeconds"`
	RefreshTimeoutSeconds  int    `json:"refreshTimeoutSeconds"`
}

type d12Observation struct {
	Name      string             `json:"name"`
	FeedEpoch int                `json:"feedEpoch"`
	Status    imagetrust.Status  `json:"status"`
	History   imagetrust.History `json:"history"`
}

type d12FeedPlan struct {
	Epoch      int    `json:"epoch"`
	Status     int    `json:"status"`
	BodySHA256 string `json:"bodySHA256"`
	SHA256     string `json:"sha256"`
}

type d12FeedEvent struct {
	Schema       string `json:"schema"`
	Ordinal      int    `json:"ordinal"`
	Epoch        int    `json:"epoch"`
	PathClass    string `json:"pathClass"`
	Generation   uint64 `json:"generation"`
	Status       int    `json:"status"`
	BodySHA256   string `json:"bodySHA256"`
	Bytes        int    `json:"bytes"`
	TLS          bool   `json:"tls"`
	AuthPresent  bool   `json:"authPresent"`
	Reason       string `json:"reason"`
	SentComplete bool   `json:"sentComplete"`
}

type d12AuditBinding struct {
	OperationID string                 `json:"operationID"`
	Prepared    evidence.EvidenceEvent `json:"prepared"`
	Result      evidence.EvidenceEvent `json:"result"`
}

type d12Report struct {
	Schema string `json:"schema"`
	Action string `json:"action"`
	Case   int    `json:"case"`
	d12Material
	Authority                    string                    `json:"authority"`
	GraphOrigin                  string                    `json:"graphOrigin"`
	Authorization                string                    `json:"authorization"`
	Production                   bool                      `json:"production"`
	DeviceActionsExecuted        bool                      `json:"deviceActionsExecuted"`
	Cases                        []d11Case                 `json:"cases"`
	Observations                 []d12Observation          `json:"observations"`
	FeedPlans                    []d12FeedPlan             `json:"feedPlans"`
	Inspection                   *truststate.Inspection    `json:"inspection,omitempty"`
	Journal                      []truststate.JournalEntry `json:"journal,omitempty"`
	Audit                        *evidence.VerifyReport    `json:"audit,omitempty"`
	AuditBindings                []d12AuditBinding         `json:"auditBindings,omitempty"`
	JournalAuditBindingsVerified bool                      `json:"journalAuditBindingsVerified"`
}

func d12Require(t *testing.T, ok bool) {
	t.Helper()
	if !ok {
		t.Fatal("isolated product lifecycle fixture rejected")
	}
}

func d12Endpoint(root, kind string) string {
	return filepath.Join(root, "refresh", kind)
}

func d12FeedDirectory(root, kind string) string {
	return filepath.Join(root, "source", kind, "feed")
}

func d12ReportPath(root, kind, action string, number int) string {
	if action == "exercise" || action == "resume" {
		action += "-" + strconv.Itoa(number)
	}
	return filepath.Join(root, "evidence", "product-lifecycle-"+kind+"-"+action+".json")
}

func d12NewReport(info d12Material, action string, number int) d12Report {
	return d12Report{Schema: "chengwang.product-lifecycle-action/v1", Action: action, Case: number,
		d12Material: info, Authority: "EPHEMERAL_TEST_ONLY", GraphOrigin: "NORMAL_TLS_REGISTRY_READBACK_MATCHED_UPLOAD",
		Authorization: "BLOCKED", Cases: []d11Case{}, Observations: []d12Observation{}, FeedPlans: []d12FeedPlan{}}
}

func d12Save(t *testing.T, root string, report d12Report) {
	t.Helper()
	d11Dir(t, filepath.Join(root, "evidence"))
	d11JSON(t, d12ReportPath(root, report.Kind, report.Action, report.Case), report)
}

func d12Load(t *testing.T, root, kind, action string, number int) d12Report {
	t.Helper()
	var report d12Report
	d11Decode(t, d11Read(t, d12ReportPath(root, kind, action, number), 4<<20), &report)
	d12Require(t, report.Schema == "chengwang.product-lifecycle-action/v1" && report.Action == action && report.Case == number && report.Kind == kind && report.Authorization == "BLOCKED" && !report.Production && !report.DeviceActionsExecuted)
	return report
}

func TestProductLifecycleD12Fixture(t *testing.T) {
	root, kind := os.Getenv("CHENGWANG_D12_ROOT"), os.Getenv("CHENGWANG_D12_KIND")
	commit, imageID := os.Getenv("CHENGWANG_D12_COMMIT"), os.Getenv("CHENGWANG_D12_IMAGE_ID")
	d12Require(t, os.Getuid() == 10001 && os.Geteuid() == 10001 && os.Getgid() == 10001 && os.Getegid() == 10001)
	d12Require(t, regexp.MustCompile(`^/tmp/chengwang-product-lifecycle-[0-9a-f]{32}$`).MatchString(root) && (kind == "message-signature" || kind == "dsse"))
	d12Require(t, regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(commit) && regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(imageID))
	d11Dir(t, root)
	d11Dir(t, filepath.Join(root, "refresh"))
	d11Dir(t, filepath.Join(root, "source"))
	d12Require(t, string(d11Read(t, filepath.Join(root, ".fixture-owner"), 64)) == strings.TrimPrefix(root, "/tmp/chengwang-product-lifecycle-")+"\n")
	d12Require(t, os.Getenv("CHENGWANG_D12_ARCHIVE") == filepath.Join(root, "bin", "product-image.private.tar"))
	// Reuse existing pure fixture helpers without broadening their public inputs
	// or mutating the original D11 fixture files. These env values live only in
	// this tagged driver process, never in the product process under test.
	t.Setenv("CHENGWANG_D11_KIND", kind)
	t.Setenv("CHENGWANG_D11_ARCHIVE", os.Getenv("CHENGWANG_D12_ARCHIVE"))
	action := os.Getenv("CHENGWANG_D12_ACTION")
	number, err := strconv.Atoi(os.Getenv("CHENGWANG_D12_CASE"))
	d12Require(t, err == nil && strconv.Itoa(number) == os.Getenv("CHENGWANG_D12_CASE"))
	switch action {
	case "prepare":
		d12Require(t, number == 0)
		d12Prepare(t, root, kind, commit, imageID)
	case "exercise", "resume":
		d12Require(t, number >= 1 && ((action == "exercise" && number <= 9) || (action == "resume" && number <= 6)))
		d12Running(t, root, kind, commit, imageID, action, number)
	case "reopen-first", "reopen-final":
		d12Require(t, number == 0)
		d12Reopen(t, root, kind, commit, imageID, action)
	default:
		d12Require(t, false)
	}
	fmt.Printf("D12_PRODUCT_LIFECYCLE_%s=PASS kind=%s case=%d authorization=BLOCKED production=false\n", strings.ReplaceAll(strings.ToUpper(action), "-", "_"), kind, number)
}

func d12PlanBytes(t *testing.T, epoch, status int, body string) []byte {
	t.Helper()
	d12Require(t, epoch >= 1 && epoch <= 7 && (status == 200 || status == 503))
	d12Require(t, status == 503 && body == "" || status == 200 && regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(body))
	// No optional oneShot field and no terminal newline: independently
	// reconstructible sorted-map encoding, not an opaque driver assertion.
	return encode(t, map[string]any{"schema": "chengwang.product-lifecycle-feed-plan/v1", "epoch": epoch,
		"responses": map[string]any{"latest.json": map[string]any{"status": status, "bodySHA256": body}}})
}

func d12Publish(t *testing.T, root, kind string, epoch, status int, body string, initial bool) d12FeedPlan {
	t.Helper()
	endpoint := filepath.Join(root, "source", kind)
	feed := d12FeedDirectory(root, kind)
	d11Dir(t, feed)
	raw := d12PlanBytes(t, epoch, status, body)
	if initial {
		d12Require(t, epoch == 1 && status == 503)
		d11Write(t, filepath.Join(feed, "plan.json"), raw)
	} else {
		temporary := filepath.Join(endpoint, "feed-plan-"+strconv.Itoa(epoch)+".private.json")
		d11Write(t, temporary, raw)
		d12Require(t, os.Rename(temporary, filepath.Join(feed, "plan.json")) == nil)
	}
	directory, err := os.Open(feed)
	d12Require(t, err == nil && directory.Sync() == nil && directory.Close() == nil)
	d12Require(t, bytes.Equal(d11Read(t, filepath.Join(feed, "plan.json"), 64<<10), raw))
	return d12FeedPlan{Epoch: epoch, Status: status, BodySHA256: body, SHA256: strings.TrimPrefix(hashed(raw), "sha256:")}
}

func d12Prepare(t *testing.T, root, kind, commit, imageID string) {
	t.Helper()
	endpoint := d12Endpoint(root, kind)
	d11Mkdir(t, endpoint)
	d11Mkdir(t, filepath.Join(endpoint, "data"))
	d11Mkdir(t, filepath.Join(root, "source", kind))
	d11Mkdir(t, d12FeedDirectory(root, kind))
	d11Mkdir(t, filepath.Join(d12FeedDirectory(root, kind), "bodies"))
	manifest, config, layers, diffIDs := d11Archive(t, root, commit, imageID)
	d11Upload(t, root, endpoint, manifest, config, layers)
	registryPEM, _ := pem.Decode(d11Read(t, filepath.Join(root, "registry-cert.pem"), 256<<10))
	sourcePEM, _ := pem.Decode(d11Read(t, filepath.Join(root, "source-cert.pem"), 256<<10))
	d12Require(t, registryPEM != nil && sourcePEM != nil)
	registryCertificate, err := x509.ParseCertificate(registryPEM.Bytes)
	d12Require(t, err == nil)
	sourceCertificate, err := x509.ParseCertificate(sourcePEM.Bytes)
	d12Require(t, err == nil && sourceCertificate.VerifyHostname("feed.fixture.invalid") == nil)
	registrySPKI, sourceSPKI := hashed(registryCertificate.RawSubjectPublicKeyInfo), hashed(sourceCertificate.RawSubjectPublicKeyInfo)
	d12Require(t, sourceSPKI != registrySPKI)
	signatureKind := verifier.KindMessageSignature
	if kind == "dsse" {
		signatureKind = verifier.KindDSSE
	}
	bundle, _, trustedRoot, expected, _ := signedBundlePair(t, signatureKind, manifest, append(bytes.Clone(manifest), '\n'), d11Repository)
	materials := make([]managedMaterial, 0, 3)
	policies := make([]d11Policy, 0, 3)
	for _, name := range []string{"a", "b", "c"} {
		m := material{manifest: manifest, config: config, bundle: bundle, root: trustedRoot,
			repository: d11Repository, reference: d11Repository + "@" + hashed(manifest)}
		approveImage(t, &m, expected, registrySPKI)
		var envelope struct {
			Payload   []byte `json:"payload"`
			Signature []byte `json:"signature"`
		}
		d11Decode(t, m.approval, &envelope)
		var document map[string]any
		d12Require(t, json.Unmarshal(envelope.Payload, &document) == nil)
		document["policyID"] = "d12-" + name
		// The intermediate template is never accepted as authority: the helper
		// below reissues its approval under a fresh real ephemeral signing key.
		envelope.Payload = encode(t, document)
		m.approval = encode(t, envelope)
		managed := newManagedMaterial(t, m)
		materials = append(materials, managed)
		policies = append(policies, d11Policy{Name: name, PolicyID: "d12-" + name,
			GrantID: managed.document.Grants[0].ID, ApprovalSHA256: managed.trust.PolicySHA256,
			ApprovalEnvelopeSHA256: hashed(managed.approval), BundleSHA256: hashed(bundle),
			BundleArtifactSHA256: hashed(manifest), TrustedRootSHA256: hashed(trustedRoot), RegistrySPKI: registrySPKI})
		d11Write(t, filepath.Join(endpoint, name+"-approval.private.json"), managed.approval)
		d11Write(t, filepath.Join(endpoint, name+"-bundle.private.json"), bundle)
	}
	document := materials[0].document
	for _, other := range materials[1:] {
		document.Approvers = append(document.Approvers, other.document.Approvers...)
		document.Grants = append(document.Grants, other.document.Grants...)
		for policy, floor := range other.document.PolicyFloors {
			document.PolicyFloors[policy] = floor
		}
	}
	catalogue1 := signManagedCatalogue(t, document, materials[0].rootKey)
	anchor := materials[0].anchor
	anchor.InitialSHA256 = hashed(catalogue1)
	document.Generation = 2
	document.Grants = []trustcatalog.Grant{document.Grants[0], document.Grants[2]}
	document.RevokedApprovals = []string{policies[1].ApprovalSHA256}
	catalogue2 := signManagedCatalogue(t, document, materials[0].rootKey)
	replayed, err := trustcatalog.Replay(anchor, [][]byte{catalogue1, catalogue2})
	d12Require(t, err == nil && replayed.ValidAt(time.Now()) && replayed.Generation() == 2)
	d11Write(t, filepath.Join(endpoint, "catalogue1.private.json"), catalogue1)
	d11Write(t, filepath.Join(endpoint, "catalogue2.private.json"), catalogue2)
	d11Write(t, filepath.Join(d12FeedDirectory(root, kind), "bodies", strings.TrimPrefix(hashed(catalogue2), "sha256:")+".json"), catalogue2)
	d11Write(t, filepath.Join(endpoint, "trusted-root.private.json"), trustedRoot)
	d11JSON(t, filepath.Join(endpoint, "anchor.json"), anchor)
	for _, name := range []string{"api-ca.pem", "api-cert.pem", "api-key.private.pem", "registry-ca.pem", "source-ca.pem"} {
		d11Write(t, filepath.Join(endpoint, name), d11Read(t, filepath.Join(root, name), 256<<10))
	}
	d12Require(t, !bytes.Equal(d11Read(t, filepath.Join(root, "source-ca.pem"), 256<<10), d11Read(t, filepath.Join(root, "api-ca.pem"), 256<<10)))
	d12Require(t, !bytes.Equal(d11Read(t, filepath.Join(root, "source-ca.pem"), 256<<10), d11Read(t, filepath.Join(root, "registry-ca.pem"), 256<<10)))
	store, err := truststate.Create(context.Background(), filepath.Join(endpoint, "trust"), anchor, catalogue1)
	d12Require(t, err == nil)
	inspection, err := store.Inspect(context.Background())
	d12Require(t, err == nil && inspection.Sequence == 1 && inspection.LedgerUsed == 0 && inspection.Catalogue.Generation == 1 && store.Close() == nil)
	audit, err := evidence.Open(filepath.Join(endpoint, "data", "evidence"))
	d12Require(t, err == nil && audit.Close() == nil)
	scope := d12Scope(anchor.StoreID)
	management := scope
	management.ObjectType, management.ObjectID = "control-plane", "d12-management"
	token, tokenHash, err := authn.GenerateToken(32)
	d12Require(t, err == nil)
	d11Write(t, filepath.Join(endpoint, "admin-token.private"), []byte(token))
	d11JSON(t, filepath.Join(endpoint, "identities.json"), authn.File{Version: authn.FileVersion,
		Identities: []authn.Identity{{TokenID: "d12-admin-token", TokenHash: tokenHash,
			Principal: authz.Principal{ID: "d12-admin", TenantID: scope.TenantID, Roles: []authz.Role{authz.RoleAdmin}, AllowedScopes: []authz.ResourceScope{scope, management}}}}})
	port := "17821"
	if kind == "dsse" {
		port = "17822"
	}
	common := map[string]any{"addr": "127.0.0.1:" + port, "identitiesFile": filepath.Join(endpoint, "identities.json"),
		"tlsCertFile": filepath.Join(endpoint, "api-cert.pem"), "tlsKeyFile": filepath.Join(endpoint, "api-key.private.pem"),
		"tenantId": scope.TenantID, "siteId": scope.SiteID, "environment": "candidate"}
	trustConfig := map[string]any{}
	for key, value := range common {
		trustConfig[key] = value
	}
	trustConfig["storePath"], trustConfig["anchorFile"] = filepath.Join(endpoint, "trust"), filepath.Join(endpoint, "anchor.json")
	trustConfig["auditDir"], trustConfig["registryCAFile"] = filepath.Join(endpoint, "data", "evidence"), filepath.Join(endpoint, "registry-ca.pem")
	trustConfig["writesEnabled"], trustConfig["webDir"] = true, "/app/web"
	trustConfig["refreshEnabled"], trustConfig["refreshURL"], trustConfig["refreshIP"] = true, d12FeedURL, "127.0.0.1"
	trustConfig["refreshSPKI"], trustConfig["refreshCAFile"] = sourceSPKI, filepath.Join(endpoint, "source-ca.pem")
	trustConfig["refreshIntervalSeconds"], trustConfig["refreshMaxAgeSeconds"], trustConfig["refreshTimeoutSeconds"] = 2, 15, 2
	d11JSON(t, filepath.Join(endpoint, "trust-config.json"), trustConfig)
	common["dataDir"], common["managementObjectId"] = filepath.Join(endpoint, "data"), management.ObjectID
	d11JSON(t, filepath.Join(endpoint, "product-config.json"), common)
	info := d12Material{d11Material: d11Material{Kind: kind, SourceCommit: commit, LocalImageID: imageID,
		ManifestSHA256: hashed(manifest), ConfigSHA256: hashed(config), LayerSHA256s: []string{}, DiffIDs: diffIDs,
		Catalogue1SHA256: hashed(catalogue1), Catalogue2SHA256: hashed(catalogue2), StoreID: anchor.StoreID, Anchor: anchor, Policies: policies},
		FeedURL: d12FeedURL, FeedSPKI: sourceSPKI, FeedCASHA256: hashed(d11Read(t, filepath.Join(root, "source-ca.pem"), 256<<10)),
		RefreshIntervalSeconds: 2, RefreshMaxAgeSeconds: 15, RefreshTimeoutSeconds: 2}
	for _, layer := range layers {
		info.LayerSHA256s = append(info.LayerSHA256s, hashed(layer))
	}
	d11JSON(t, filepath.Join(endpoint, "materials.private.json"), info)
	report := d12NewReport(info, "prepare", 0)
	report.FeedPlans = append(report.FeedPlans, d12Publish(t, root, kind, 1, 503, "", true))
	d12Save(t, root, report)
}

func d12Scope(storeID string) authz.ResourceScope {
	return authz.ResourceScope{TenantID: "d12-tenant", SiteID: "d12-site", ObjectType: "image-trust", ObjectID: storeID, Environment: "candidate"}
}

func d12Info(t *testing.T, root, kind, commit, imageID string) d12Material {
	t.Helper()
	var info d12Material
	d11Decode(t, d11Read(t, filepath.Join(d12Endpoint(root, kind), "materials.private.json"), 256<<10), &info)
	d11Decode(t, d11Read(t, filepath.Join(d12Endpoint(root, kind), "anchor.json"), 8<<10), &info.Anchor)
	d12Require(t, info.Kind == kind && info.SourceCommit == commit && info.LocalImageID == imageID && info.ConfigSHA256 == imageID && len(info.Policies) == 3 && reflect.DeepEqual(info.LayerSHA256s, info.DiffIDs))
	d12Require(t, info.StoreID == info.Anchor.StoreID && info.Anchor.InitialSHA256 == info.Catalogue1SHA256 && info.FeedURL == d12FeedURL && info.RefreshIntervalSeconds == 2 && info.RefreshMaxAgeSeconds == 15 && info.RefreshTimeoutSeconds == 2)
	for index, name := range []string{"a", "b", "c"} {
		d12Require(t, info.Policies[index].Name == name && info.Policies[index].PolicyID == "d12-"+name && info.Policies[index].BundleArtifactSHA256 == info.ManifestSHA256)
	}
	return info
}

func d12ReadAPI(t *testing.T, ctx context.Context, client *http.Client, target, token string, destination any) bool {
	t.Helper()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	d12Require(t, err == nil)
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
	d12Require(t, response.StatusCode == 200 && len(raw) <= 4<<20)
	d11Decode(t, raw, destination)
	return true
}

func d12Snapshot(t *testing.T, client *http.Client, root, kind, token string) (imagetrust.Status, imagetrust.History) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	for ctx.Err() == nil {
		var status imagetrust.Status
		var history imagetrust.History
		if d12ReadAPI(t, ctx, client, d11APIBase(kind)+"/api/v1/image-trust", token, &status) &&
			d12ReadAPI(t, ctx, client, d11APIBase(kind)+"/api/v1/image-trust/history?limit=50", token, &history) {
			acknowledged := true
			for _, entry := range history.Entries {
				acknowledged = acknowledged && entry.Acknowledged && len(entry.PreparedAuditHash) == 64 && len(entry.ResultAuditHash) == 64
			}
			if history.Sequence == status.Sequence && history.Total == len(history.Entries) && acknowledged && status.Healthy {
				d12Require(t, status.Boundary == imagetrust.StatusBoundary && status.Authorization == "BLOCKED" && !status.DeviceActionsExecuted && status.Fresh && status.RefreshRequired && status.NotAfterUnix > time.Now().Unix())
				d12Require(t, history.Boundary == imagetrust.HistoryBoundary && history.Authorization == "BLOCKED" && !history.DeviceActionsExecuted)
				return status, history
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	d12Require(t, false)
	return imagetrust.Status{}, imagetrust.History{}
}

func d12SameDomain(left, right imagetrust.Status, before, after imagetrust.History) bool {
	return left.Sequence == right.Sequence && left.Generation == right.Generation && left.CatalogueSHA256 == right.CatalogueSHA256 &&
		left.StoreID == right.StoreID && left.NotAfterUnix == right.NotAfterUnix && left.LedgerEntries == right.LedgerEntries &&
		left.Consumed == right.Consumed && left.Reserved == right.Reserved && left.RevokedApprovals == right.RevokedApprovals &&
		left.RevokedKeys == right.RevokedKeys && left.RevokedManifests == right.RevokedManifests && reflect.DeepEqual(left.Policies, right.Policies) &&
		before.Sequence == after.Sequence && before.Total == after.Total && reflect.DeepEqual(before.Entries, after.Entries)
}

func d12Wait(t *testing.T, client *http.Client, root, kind, token string, predicate func(imagetrust.Status, imagetrust.History) bool) (imagetrust.Status, imagetrust.History) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		status, history := d12Snapshot(t, client, root, kind, token)
		if predicate(status, history) {
			return status, history
		}
		time.Sleep(100 * time.Millisecond)
	}
	d12Require(t, false)
	return imagetrust.Status{}, imagetrust.History{}
}

func d12LastObservation(t *testing.T, report d12Report) d12Observation {
	t.Helper()
	d12Require(t, len(report.Observations) == 2 && report.Observations[0].Name == "before" && report.Observations[1].Name == "after")
	return report.Observations[1]
}

func d12Previous(t *testing.T, root, kind, action string, number int) d12Report {
	t.Helper()
	if number > 1 {
		return d12Load(t, root, kind, action, number-1)
	}
	if action == "exercise" {
		return d12Load(t, root, kind, "prepare", 0)
	}
	reopened := d12Load(t, root, kind, "reopen-first", 0)
	d12Require(t, reopened.JournalAuditBindingsVerified)
	return d12Load(t, root, kind, "exercise", 9)
}

func d12ExpectedBefore(t *testing.T, report d12Report, before imagetrust.Status, history imagetrust.History, action string, number int, info d12Material) int {
	t.Helper()
	if action == "exercise" && number == 1 {
		d12Require(t, report.Action == "prepare" && before.Sequence == 1 && before.Generation == 1 && before.CatalogueSHA256 == info.Catalogue1SHA256 && before.LedgerEntries == 0 && before.Consumed == 0 && before.Reserved == 0 && history.Total == 0)
		return 1
	}
	previous := d12LastObservation(t, report)
	d12Require(t, d12SameDomain(previous.Status, before, previous.History, history))
	return previous.FeedEpoch
}

func d12ReadFeedEvents(t *testing.T, root, kind string) ([]d12FeedEvent, bool) {
	t.Helper()
	directory := d12FeedDirectory(root, kind)
	d11Dir(t, filepath.Join(root, "source"))
	d11Dir(t, filepath.Join(root, "source", kind))
	d11Dir(t, directory)
	name := filepath.Join(directory, "events.jsonl")
	fd, err := unix.Open(name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, false
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var before, after, named unix.Stat_t
	d12Require(t, unix.Fstat(fd, &before) == nil && before.Mode&unix.S_IFMT == unix.S_IFREG && before.Mode&07777 == 0600 && before.Uid == 10001 && before.Gid == 10001 && before.Nlink == 1 && before.Size >= 0 && before.Size <= 8<<20)
	raw, err := io.ReadAll(io.LimitReader(file, (8<<20)+1))
	d12Require(t, err == nil && len(raw) <= 8<<20 && unix.Fstat(fd, &after) == nil && unix.Lstat(name, &named) == nil)
	d12Require(t, named.Dev == before.Dev && named.Ino == before.Ino && after.Mode == before.Mode && after.Uid == before.Uid && after.Gid == before.Gid && after.Nlink == 1 && named.Mode == before.Mode && named.Uid == before.Uid && named.Gid == before.Gid && named.Nlink == 1)
	if len(raw) == 0 {
		return []d12FeedEvent{}, true
	}
	if raw[len(raw)-1] != '\n' {
		return nil, false // An append in progress is not evidence of zero HTTP.
	}
	rows := bytes.Split(raw[:len(raw)-1], []byte{'\n'})
	result := make([]d12FeedEvent, 0, len(rows))
	for index, row := range rows {
		// The log is flat. Check every field once before decoding; the standard
		// JSON struct decoder alone would silently accept duplicate field names.
		decoder := json.NewDecoder(bytes.NewReader(row))
		start, err := decoder.Token()
		d12Require(t, err == nil && start == json.Delim('{'))
		seen := map[string]bool{}
		for decoder.More() {
			value, err := decoder.Token()
			key, ok := value.(string)
			d12Require(t, err == nil && ok && !seen[key])
			seen[key] = true
			var field json.RawMessage
			d12Require(t, decoder.Decode(&field) == nil)
		}
		end, err := decoder.Token()
		d12Require(t, err == nil && end == json.Delim('}') && decoder.Decode(new(any)) == io.EOF && len(seen) == 12)
		var event d12FeedEvent
		d11Decode(t, row, &event)
		d12Require(t, event.Schema == "chengwang.product-lifecycle-feed-event/v1" && event.Ordinal == index+1 && (event.PathClass == "latest" || event.PathClass == "generation" || event.PathClass == "invalid") && (event.Status == 200 || event.Status == 503) && regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(event.BodySHA256) && event.Bytes >= 0 && event.TLS && (!event.SentComplete && event.Bytes == 0 || event.SentComplete))
		result = append(result, event)
	}
	return result, true
}

func d12WaitUnavailableSource(t *testing.T, root, kind string, epoch int) {
	t.Helper()
	deadline := time.Now().Add(12 * time.Second)
	errorBody := []byte("{\"code\":\"fixture_feed_unavailable\"}\n")
	for time.Now().Before(deadline) {
		rows, complete := d12ReadFeedEvents(t, root, kind)
		if complete {
			for _, event := range rows {
				if event.Epoch == epoch && event.PathClass == "latest" && event.Generation == 0 && event.Status == 503 && event.SentComplete && !event.AuthPresent && event.Reason == "planned-unavailable" && event.Bytes == len(errorBody) && event.BodySHA256 == strings.TrimPrefix(hashed(errorBody), "sha256:") {
					return
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	d12Require(t, false)
}

func d12Post(t *testing.T, client *http.Client, root, kind, token, name string, policyIndex, want int, info d12Material, before imagetrust.Status, history imagetrust.History) d11Case {
	t.Helper()
	policy := info.Policies[policyIndex]
	endpoint := d12Endpoint(root, kind)
	approval := d11Read(t, filepath.Join(endpoint, policy.Name+"-approval.private.json"), 64<<10)
	bundle := d11Read(t, filepath.Join(endpoint, policy.Name+"-bundle.private.json"), 1<<20)
	trustedRoot := d11Read(t, filepath.Join(endpoint, "trusted-root.private.json"), 1<<20)
	d12Require(t, hashed(approval) == policy.ApprovalEnvelopeSHA256 && hashed(bundle) == policy.BundleSHA256 && hashed(trustedRoot) == policy.TrustedRootSHA256)
	body := encode(t, imagetrust.VerifyRequest{PolicyID: policy.PolicyID, Approval: approval, Bundle: bundle, TrustedRoot: trustedRoot})
	result := d11Case{Name: name, Method: "POST", Path: d11VerifyPath, PolicyID: policy.PolicyID, GrantID: policy.GrantID,
		ApprovalSHA256: policy.ApprovalSHA256, ApprovalEnvelopeSHA256: policy.ApprovalEnvelopeSHA256,
		BundleSHA256: policy.BundleSHA256, TrustedRootSHA256: policy.TrustedRootSHA256,
		RequestSHA256: hashed(body), StatusBefore: before, HistoryBefore: history}
	status, _, raw := d11HTTP(t, client, "POST", d11APIBase(kind)+d11VerifyPath, token, "application/json", body)
	d12Require(t, status == want)
	result.HTTPStatus = status
	if status == 200 {
		var receipt imagetrust.Receipt
		d11Decode(t, raw, &receipt)
		d12Require(t, receipt.Boundary == imagetrust.VerifiedBoundary && receipt.Authorization == "BLOCKED" && !receipt.DeviceActionsExecuted && receipt.Verified && receipt.Generation == 2 && receipt.CatalogueSHA256 == info.Catalogue2SHA256 && receipt.GrantID == policy.GrantID && receipt.ManifestSHA256 == info.ManifestSHA256 && regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(receipt.EvidenceSHA256))
		result.Receipt = &receipt
	} else {
		var failure struct {
			Boundary              string `json:"boundary"`
			Authorization         string `json:"authorization"`
			DeviceActionsExecuted bool   `json:"deviceActionsExecuted"`
			Code                  string `json:"code"`
			StateMayHaveChanged   bool   `json:"stateMayHaveChanged"`
		}
		d11Decode(t, raw, &failure)
		code, changed := "image_trust_invalid", true
		if status == 503 {
			code, changed = "image_trust_unavailable", false
		}
		d12Require(t, failure.Boundary == imagetrust.StatusBoundary && failure.Authorization == "BLOCKED" && !failure.DeviceActionsExecuted && failure.Code == code && failure.StateMayHaveChanged == changed)
		result.ErrorCode, result.StateMayHaveChanged = failure.Code, failure.StateMayHaveChanged
	}
	result.StatusAfter, result.HistoryAfter = d12Snapshot(t, client, root, kind, token)
	if status == 503 {
		d12Require(t, d12SameDomain(before, result.StatusAfter, history, result.HistoryAfter))
	} else {
		delta := uint64(4)
		if status == 200 {
			delta++
		}
		d12Require(t, result.StatusAfter.Sequence == before.Sequence+delta && result.HistoryAfter.Total == history.Total+1 && result.StatusAfter.Generation == 2 && result.StatusAfter.CatalogueSHA256 == info.Catalogue2SHA256)
	}
	return result
}

func d12Running(t *testing.T, root, kind, commit, imageID, action string, number int) {
	t.Helper()
	info := d12Info(t, root, kind, commit, imageID)
	previous := d12Previous(t, root, kind, action, number)
	d12Require(t, reflect.DeepEqual(encode(t, previous.d12Material), encode(t, info)))
	endpoint := d12Endpoint(root, kind)
	d11Write(t, filepath.Join(endpoint, "intent-"+action+"-"+strconv.Itoa(number)+".private"), []byte("SINGLE_ATTEMPT_ONLY\n"))
	client := d11Client(t, root, false)
	client.Timeout = 10 * time.Second
	token := string(d11Read(t, filepath.Join(endpoint, "admin-token.private"), 512))
	before, historyBefore := d12Snapshot(t, client, root, kind, token)
	epoch := d12ExpectedBefore(t, previous, before, historyBefore, action, number, info)
	planStatus, planBody := 503, ""
	if epoch == 2 || epoch == 4 || epoch == 6 {
		planStatus, planBody = 200, strings.TrimPrefix(info.Catalogue2SHA256, "sha256:")
	}
	d12Require(t, bytes.Equal(d11Read(t, filepath.Join(d12FeedDirectory(root, kind), "plan.json"), 64<<10), d12PlanBytes(t, epoch, planStatus, planBody)))
	report := d12NewReport(info, action, number)
	report.Observations = append(report.Observations, d12Observation{"before", epoch, before, historyBefore})
	after, historyAfter := before, historyBefore
	post := func(name string, policy, want int) {
		result := d12Post(t, client, root, kind, token, name, policy, want, info, after, historyAfter)
		report.Cases = append(report.Cases, result)
		after, historyAfter = result.StatusAfter, result.HistoryAfter
	}
	publish := func(next, status int) {
		body := ""
		if status == 200 {
			body = strings.TrimPrefix(info.Catalogue2SHA256, "sha256:")
		}
		report.FeedPlans = append(report.FeedPlans, d12Publish(t, root, kind, next, status, body, false))
		epoch = next
	}
	fresh := func() {
		after, historyAfter = d12Wait(t, client, root, kind, token, func(status imagetrust.Status, history imagetrust.History) bool {
			return status.Generation == 2 && status.CatalogueSHA256 == info.Catalogue2SHA256 && status.RefreshFresh && status.RefreshLastSuccessUnix > 0 && status.RefreshUntilUnix > time.Now().Unix()
		})
	}
	if action == "exercise" {
		switch number {
		case 1:
			d12Require(t, !before.RefreshFresh && before.RefreshLastSuccessUnix == 0 && before.RefreshUntilUnix == 0)
			d12WaitUnavailableSource(t, root, kind, 1)
			post("unconfirmed", 0, 503)
		case 2:
			publish(2, 200)
			fresh()
			d12Require(t, after.Sequence == 5 && historyAfter.Total == 1 && after.LedgerEntries == 0 && after.RevokedApprovals == 1 && historyAfter.Entries[0].ActorID == "image-trust-refresh" && historyAfter.Entries[0].Kind == "update" && historyAfter.Entries[0].Outcome == truststate.OutcomeCatalogueCommitted)
		case 3:
			d12Require(t, before.RefreshFresh)
			after, historyAfter = d12Wait(t, client, root, kind, token, func(status imagetrust.Status, history imagetrust.History) bool {
				return status.RefreshFresh && status.RefreshLastSuccessUnix > before.RefreshLastSuccessUnix && status.RefreshUntilUnix > before.RefreshUntilUnix
			})
			d12Require(t, d12SameDomain(before, after, historyBefore, historyAfter))
		case 4:
			d12Require(t, before.RefreshFresh)
			post("a-success", 0, 200)
		case 5:
			d12Require(t, before.RefreshFresh)
			post("a-replay", 0, 400)
		case 6:
			d12Require(t, before.RefreshFresh)
			post("b-revoked", 1, 400)
		case 7:
			publish(3, 503)
			after, historyAfter = d12Wait(t, client, root, kind, token, func(status imagetrust.Status, history imagetrust.History) bool {
				return !status.RefreshFresh && status.RefreshUntilUnix > 0 && time.Now().Unix() > status.RefreshUntilUnix
			})
			d12Require(t, d12SameDomain(before, after, historyBefore, historyAfter))
			post("stale", 2, 503)
		case 8:
			publish(4, 200)
			fresh()
			d12Require(t, d12SameDomain(before, after, historyBefore, historyAfter) && after.RefreshLastSuccessUnix > before.RefreshLastSuccessUnix)
		case 9:
			publish(5, 503)
			after, historyAfter = d12Snapshot(t, client, root, kind, token)
			d12Require(t, d12SameDomain(before, after, historyBefore, historyAfter))
		}
	} else {
		switch number {
		case 1:
			d12Require(t, before.Generation == 2 && before.CatalogueSHA256 == info.Catalogue2SHA256 && !before.RefreshFresh && before.RefreshLastSuccessUnix == 0 && before.RefreshUntilUnix == 0)
			d12WaitUnavailableSource(t, root, kind, 5)
			post("cold-unconfirmed", 2, 503)
		case 2:
			publish(6, 200)
			fresh()
			d12Require(t, d12SameDomain(before, after, historyBefore, historyAfter))
		case 3:
			d12Require(t, before.RefreshFresh)
			post("a-replay-after-restart", 0, 400)
		case 4:
			d12Require(t, before.RefreshFresh)
			post("c-success", 2, 200)
		case 5:
			d12Require(t, before.RefreshFresh)
			post("c-replay", 2, 400)
		case 6:
			publish(7, 503)
			after, historyAfter = d12Snapshot(t, client, root, kind, token)
			d12Require(t, d12SameDomain(before, after, historyBefore, historyAfter))
		}
	}
	d12Require(t, after.Reserved == 0 && after.LedgerEntries == after.Consumed)
	report.Observations = append(report.Observations, d12Observation{"after", epoch, after, historyAfter})
	d12Save(t, root, report)
}

func d12Reopen(t *testing.T, root, kind, commit, imageID, action string) {
	t.Helper()
	info := d12Info(t, root, kind, commit, imageID)
	previousAction, lastNumber, wantOperations, wantConsumed, wantSequence := "exercise", 9, 4, 1, uint64(18)
	if action == "reopen-final" {
		previousAction, lastNumber, wantOperations, wantConsumed, wantSequence = "resume", 6, 7, 2, 31
	}
	previous := d12Load(t, root, kind, previousAction, lastNumber)
	last := d12LastObservation(t, previous)
	endpoint := d12Endpoint(root, kind)
	store, err := truststate.Open(context.Background(), filepath.Join(endpoint, "trust"), info.Anchor)
	d12Require(t, err == nil)
	defer store.Close()
	inspection, err := store.Inspect(context.Background())
	d12Require(t, err == nil)
	journal, err := store.Journal(context.Background())
	d12Require(t, err == nil && len(journal) == wantOperations && last.History.Total == wantOperations)
	audit, err := evidence.Open(filepath.Join(endpoint, "data", "evidence"))
	d12Require(t, err == nil)
	defer audit.Close()
	proof, err := audit.Verify()
	d12Require(t, err == nil && proof.Valid && proof.Count == uint64(2*wantOperations) && proof.Count == proof.ExpectedCount && proof.LastHash == proof.ExpectedLastHash)
	view, err := audit.RecoverySnapshot()
	d12Require(t, err == nil)
	d12Require(t, inspection.Authorization == "BLOCKED" && inspection.CatalogueValid && inspection.Sequence == wantSequence && inspection.Sequence == last.Status.Sequence && inspection.Catalogue.Generation == 2 && inspection.Catalogue.SHA256 == info.Catalogue2SHA256 && inspection.LedgerUsed == wantConsumed && last.Status.Consumed == wantConsumed && last.Status.Reserved == 0)
	grants := map[string]d11Policy{info.Policies[0].GrantID: info.Policies[0]}
	if wantConsumed == 2 {
		grants[info.Policies[2].GrantID] = info.Policies[2]
	}
	d12Require(t, len(inspection.Consumptions) == wantConsumed)
	for _, consumption := range inspection.Consumptions {
		policy, ok := grants[consumption.GrantID]
		d12Require(t, ok && consumption.Status == "CONSUMED" && consumption.PolicyID == policy.PolicyID && consumption.ApprovalSHA256 == policy.ApprovalSHA256 && consumption.ManifestSHA256 == info.ManifestSHA256 && consumption.Generation == 2 && consumption.CatalogueSHA256 == info.Catalogue2SHA256)
		requestAction, requestNumber := "exercise", 4
		if policy.Name == "c" {
			requestAction, requestNumber = "resume", 4
		}
		receiptReport := d12Load(t, root, kind, requestAction, requestNumber)
		d12Require(t, len(receiptReport.Cases) == 1 && receiptReport.Cases[0].Receipt != nil && consumption.EvidenceSHA256 == receiptReport.Cases[0].Receipt.EvidenceSHA256)
	}
	report := d12NewReport(info, action, 0)
	for index, entry := range journal {
		base, ok := view.HashAt(entry.Operation.AuditBaseCount)
		d12Require(t, ok && base == entry.Operation.AuditBaseHash && entry.Operation.AuditBaseCount == uint64(index*2))
		prepared, ok := view.Lookup("image-trust/" + entry.Operation.ID + "/prepared")
		d12Require(t, ok)
		result, ok := view.Lookup("image-trust/" + entry.Operation.ID + "/result")
		d12Require(t, ok)
		actor, kindExpected, resultExpected := "d12-admin", "verify", "rejected"
		outcome := truststate.OutcomeRejected
		if index == 0 {
			actor, kindExpected, resultExpected = "image-trust-refresh", "update", "completed"
			outcome = truststate.OutcomeCatalogueCommitted
		} else if index == 1 || index == 5 {
			resultExpected, outcome = "verification_consumed", truststate.OutcomeVerificationConsumed
		}
		d12Require(t, entry.Operation.ActorID == actor && entry.Operation.Kind == kindExpected && entry.Operation.ScopeSHA256 == hashed(encode(t, d12Scope(info.StoreID))) && entry.Outcome == outcome && entry.Acknowledged)
		if index == 0 {
			d12Require(t, d11SameData(entry.Operation.Data, map[string]string{"catalogueSHA256": info.Catalogue2SHA256}))
		} else {
			requestAction, requestNumber := "exercise", index+3
			if index >= 4 {
				requestAction, requestNumber = "resume", index-1
			}
			requestReport := d12Load(t, root, kind, requestAction, requestNumber)
			d12Require(t, len(requestReport.Cases) == 1)
			requestCase := requestReport.Cases[0]
			d12Require(t, d11SameData(entry.Operation.Data, map[string]string{"policyId": requestCase.PolicyID,
				"approvalSHA256": requestCase.ApprovalEnvelopeSHA256, "bundleSHA256": requestCase.BundleSHA256,
				"rootSHA256": requestCase.TrustedRootSHA256}))
			if outcome == truststate.OutcomeVerificationConsumed {
				d12Require(t, requestCase.Receipt != nil && entry.GrantID == requestCase.Receipt.GrantID && entry.CatalogueSHA256 == requestCase.Receipt.CatalogueSHA256 && entry.ManifestSHA256 == requestCase.Receipt.ManifestSHA256 && entry.EvidenceSHA256 == requestCase.Receipt.EvidenceSHA256 && entry.Generation == requestCase.Receipt.Generation)
			}
		}
		d12Require(t, prepared.ActorID == actor && result.ActorID == actor && prepared.TraceID == entry.Operation.ID && result.TraceID == entry.Operation.ID && prepared.Action == "image_trust."+kindExpected && result.Action == prepared.Action && prepared.Target == "image-trust/"+info.StoreID && result.Target == prepared.Target)
		d12Require(t, prepared.Result == "prepared" && result.Result == resultExpected && prepared.Hash == entry.Operation.PreparedAuditHash && result.Hash == entry.ResultAuditHash && d11SameData(prepared.Data, entry.Operation.Data) && d11SameData(result.Data, entry.OutcomeData))
		found := false
		for _, historical := range last.History.Entries {
			if historical.OperationID == entry.Operation.ID {
				d12Require(t, historical.ActorID == actor && historical.Kind == kindExpected && historical.State == entry.State && historical.Outcome == entry.Outcome && historical.Acknowledged && historical.PreparedAuditHash == prepared.Hash && historical.ResultAuditHash == result.Hash)
				found = true
			}
		}
		d12Require(t, found)
		report.AuditBindings = append(report.AuditBindings, d12AuditBinding{entry.Operation.ID, prepared, result})
	}
	report.Inspection, report.Journal, report.Audit, report.JournalAuditBindingsVerified = &inspection, journal, &proof, true
	d12Require(t, store.Close() == nil && audit.Close() == nil)
	d12Save(t, root, report)
}
