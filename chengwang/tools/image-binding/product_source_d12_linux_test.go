//go:build linux && productregistry && productlifecycle && productsource

package binding_test

// Wave 1 calls only the real image's read APIs. The independently running
// product worker fetches, applies and confirms; this driver never does so.
import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
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
	bolt "go.etcd.io/bbolt"
	"golang.org/x/sys/unix"
)

type sourceCatalogue struct {
	Name       string `json:"name"`
	Generation uint64 `json:"generation"`
	Raw        []byte `json:"raw"`
	SHA256     string `json:"sha256"`
}
type sourceMaterial struct {
	d12Material
	AnchorRaw   []byte            `json:"anchorRaw"`
	ApprovalRaw []byte            `json:"approvalRaw"`
	Catalogues  []sourceCatalogue `json:"catalogues"`
}
type sourcePlan struct {
	Epoch  int    `json:"epoch"`
	Raw    []byte `json:"raw"`
	SHA256 string `json:"sha256"`
}
type sourceFence struct {
	EventCount int    `json:"eventCount"`
	SHA256     string `json:"sha256"`
}
type sourceObservation struct {
	Name        string             `json:"name"`
	Status      imagetrust.Status  `json:"status"`
	History     imagetrust.History `json:"history"`
	SourceFence sourceFence        `json:"sourceFence"`
}
type sourceRawHash struct {
	Bytes  int    `json:"bytes"`
	SHA256 string `json:"sha256"`
}
type sourceOffline struct {
	Inspection        truststate.Inspection     `json:"inspection"`
	Journal           []truststate.JournalEntry `json:"journal"`
	Audit             evidence.VerifyReport     `json:"audit"`
	AuditEvents       []evidence.EvidenceEvent  `json:"auditEvents"`
	AuditBindings     []d12AuditBinding         `json:"auditBindings"`
	AuditLog          sourceRawHash             `json:"auditLog"`
	Checkpoint        sourceRawHash             `json:"checkpoint"`
	TrustRecordSHA256 string                    `json:"trustRecordSHA256"`
}
type sourceReport struct {
	Schema                string              `json:"schema"`
	SourceCommit          string              `json:"sourceCommit"`
	LocalImageID          string              `json:"localImageID"`
	Flow                  string              `json:"flow"`
	Kind                  string              `json:"kind"`
	Action                string              `json:"action"`
	Authorization         string              `json:"authorization"`
	Production            bool                `json:"production"`
	DeviceActionsExecuted bool                `json:"deviceActionsExecuted"`
	Material              sourceMaterial      `json:"material"`
	Observations          []sourceObservation `json:"observations"`
	FeedPlans             []sourcePlan        `json:"feedPlans"`
	Offline               *sourceOffline      `json:"offline"`
}
type sourceEvent struct {
	Schema               string `json:"schema"`
	Ordinal              int    `json:"ordinal"`
	Connection           int    `json:"connection"`
	Event                string `json:"event"`
	Reason               string `json:"reason"`
	Epoch                int    `json:"epoch"`
	PlanSHA256           string `json:"planSHA256"`
	PathClass            string `json:"pathClass"`
	Generation           uint64 `json:"generation"`
	Mode                 string `json:"mode"`
	Status               int    `json:"status"`
	RepresentationSHA256 string `json:"representationSHA256"`
	RepresentationBytes  int    `json:"representationBytes"`
	WireSHA256           string `json:"wireSHA256"`
	WireBytes            int    `json:"wireBytes"`
	WrittenBytes         int    `json:"writtenBytes"`
	WireComplete         bool   `json:"wireComplete"`
	AuthPresent          bool   `json:"authPresent"`
	TLS                  bool   `json:"tls"`
}

func sourceRequire(t *testing.T, ok bool) {
	t.Helper()
	if !ok {
		t.Fatal("isolated product source wave1 fixture rejected")
	}
}
func sourceEndpoint(root, flow, kind string) string {
	return filepath.Join(root, "refresh", flow, kind)
}
func sourceDirectory(root, flow, kind string) string {
	return filepath.Join(root, "source-"+flow, kind)
}
func sourceReportPath(root, flow, kind, action string) string {
	return filepath.Join(root, "evidence", "product-source-"+flow+"-"+kind+"-"+action+".json")
}
func sourceNewReport(info sourceMaterial, flow, action string) sourceReport {
	return sourceReport{Schema: "chengwang.product-source-driver/v1", SourceCommit: info.SourceCommit,
		LocalImageID: info.LocalImageID, Flow: flow, Kind: info.Kind, Action: action,
		Authorization: "BLOCKED", Material: info, Observations: []sourceObservation{}, FeedPlans: []sourcePlan{}}
}
func sourceSave(t *testing.T, root string, report sourceReport) {
	t.Helper()
	d11JSON(t, sourceReportPath(root, report.Flow, report.Kind, report.Action), report)
}
func sourceLoad(t *testing.T, root, flow, kind, action string) sourceReport {
	t.Helper()
	var report sourceReport
	d11Decode(t, d11Read(t, sourceReportPath(root, flow, kind, action), 512<<10), &report)
	sourceRequire(t, report.Schema == "chengwang.product-source-driver/v1" && report.Flow == flow && report.Kind == kind && report.Action == action && report.Authorization == "BLOCKED" && !report.Production && !report.DeviceActionsExecuted)
	d11Decode(t, report.Material.AnchorRaw, &report.Material.Anchor)
	return report
}
func sourceDir(t *testing.T, name string) {
	t.Helper()
	if _, err := os.Lstat(name); errors.Is(err, os.ErrNotExist) {
		d11Mkdir(t, name)
	} else {
		sourceRequire(t, err == nil)
		d11Dir(t, name)
	}
}
func sourceRawDigest(raw []byte) sourceRawHash {
	return sourceRawHash{len(raw), strings.TrimPrefix(hashed(raw), "sha256:")}
}
func sourceCatalogueNamed(t *testing.T, info sourceMaterial, name string) sourceCatalogue {
	t.Helper()
	for _, value := range info.Catalogues {
		if value.Name == name {
			sourceRequire(t, value.SHA256 == hashed(value.Raw))
			return value
		}
	}
	sourceRequire(t, false)
	return sourceCatalogue{}
}
func sourcePublish(t *testing.T, root, flow, kind string, epoch int, latest string, prefix bool, initial bool, info sourceMaterial) sourcePlan {
	t.Helper()
	response := func(name string) map[string]any {
		if name == "forbidden" {
			return map[string]any{"mode": "forbidden", "bodySHA256": ""}
		}
		return map[string]any{"mode": "json", "bodySHA256": strings.TrimPrefix(sourceCatalogueNamed(t, info, name).SHA256, "sha256:")}
	}
	responses := map[string]any{"latest.json": response(latest)}
	if prefix {
		responses["2.json"] = response("g2")
	}
	raw := encode(t, map[string]any{"schema": "chengwang.product-source-plan/v1", "epoch": epoch, "responses": responses})
	dir := sourceDirectory(root, flow, kind)
	path := filepath.Join(dir, "feed", "plan.json")
	if initial {
		d11Write(t, path, raw)
	} else {
		// Pending is outside feed, whose closed entry audit must never see it.
		pending := filepath.Join(dir, fmt.Sprintf(".plan-%d.private.pending", epoch))
		d11Write(t, pending, raw)
		sourceRequire(t, os.Rename(pending, path) == nil)
		for _, parent := range []string{dir, filepath.Join(dir, "feed")} {
			fd, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			sourceRequire(t, err == nil)
			syncErr, closeErr := unix.Fsync(fd), unix.Close(fd)
			sourceRequire(t, syncErr == nil && closeErr == nil)
		}
	}
	return sourcePlan{epoch, raw, hashed(raw)}
}

func TestProductSourceD12Fixture(t *testing.T) {
	root, flow, kind := os.Getenv("CHENGWANG_D12_SOURCE_ROOT"), os.Getenv("CHENGWANG_D12_SOURCE_FLOW"), os.Getenv("CHENGWANG_D12_SOURCE_KIND")
	commit, imageID, action := os.Getenv("CHENGWANG_D12_SOURCE_COMMIT"), os.Getenv("CHENGWANG_D12_SOURCE_IMAGE_ID"), os.Getenv("CHENGWANG_D12_SOURCE_ACTION")
	sourceRequire(t, os.Getuid() == 10001 && os.Geteuid() == 10001 && os.Getgid() == 10001 && os.Getegid() == 10001)
	sourceRequire(t, regexp.MustCompile(`^/tmp/chengwang-product-lifecycle-[0-9a-f]{32}$`).MatchString(root) && (kind == "message-signature" || kind == "dsse"))
	sourceRequire(t, flow == "http-recovery" || flow == "bad-signature" || flow == "prefix-recovery")
	sourceRequire(t, regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(commit) && regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(imageID))
	d11Dir(t, root)
	d11Dir(t, filepath.Join(root, "evidence"))
	sourceRequire(t, string(d11Read(t, filepath.Join(root, ".fixture-owner"), 64)) == strings.TrimPrefix(root, "/tmp/chengwang-product-lifecycle-")+"\n")
	sourceRequire(t, os.Getenv("CHENGWANG_D12_SOURCE_ARCHIVE") == filepath.Join(root, "bin", "product-image.private.tar"))
	t.Setenv("CHENGWANG_D11_KIND", kind)
	t.Setenv("CHENGWANG_D11_ARCHIVE", os.Getenv("CHENGWANG_D12_SOURCE_ARCHIVE"))
	switch action {
	case "prepare":
		sourcePrepare(t, root, flow, kind, commit, imageID)
	case "run":
		sourceRun(t, root, flow, kind, commit, imageID)
	case "reopen":
		sourceReopen(t, root, flow, kind, commit, imageID)
	default:
		sourceRequire(t, false)
	}
	fmt.Printf("D12_PRODUCT_SOURCE_%s=PASS flow=%s kind=%s authorization=BLOCKED production=false\n", strings.ToUpper(action), flow, kind)
}

func sourcePrepare(t *testing.T, root, flow, kind, commit, imageID string) {
	t.Helper()
	endpoint := sourceEndpoint(root, flow, kind)
	for _, name := range []string{filepath.Join(root, "refresh"), filepath.Join(root, "refresh", flow), endpoint,
		filepath.Join(endpoint, "data"), filepath.Join(root, "source-"+flow), sourceDirectory(root, flow, kind),
		filepath.Join(sourceDirectory(root, flow, kind), "feed"), filepath.Join(sourceDirectory(root, flow, kind), "feed", "bodies")} {
		sourceDir(t, name)
	}
	manifest, config, layers, diffIDs := d11Archive(t, root, commit, imageID)
	d11Upload(t, root, endpoint, manifest, config, layers)
	registryPEM, _ := pem.Decode(d11Read(t, filepath.Join(root, "registry-cert.pem"), 256<<10))
	feedPEM, _ := pem.Decode(d11Read(t, filepath.Join(root, "source-cert.pem"), 256<<10))
	sourceRequire(t, registryPEM != nil && feedPEM != nil)
	registryCert, err := x509.ParseCertificate(registryPEM.Bytes)
	sourceRequire(t, err == nil && registryCert.VerifyHostname("registry.fixture.invalid") == nil)
	feedCert, err := x509.ParseCertificate(feedPEM.Bytes)
	sourceRequire(t, err == nil && feedCert.VerifyHostname("feed.fixture.invalid") == nil)
	registrySPKI, feedSPKI := hashed(registryCert.RawSubjectPublicKeyInfo), hashed(feedCert.RawSubjectPublicKeyInfo)
	sourceRequire(t, registrySPKI != feedSPKI)
	signatureKind := verifier.KindMessageSignature
	if kind == "dsse" {
		signatureKind = verifier.KindDSSE
	}
	bundle, _, trustedRoot, expected, _ := signedBundlePair(t, signatureKind, manifest, append(bytes.Clone(manifest), '\n'), d11Repository)
	m := material{manifest: manifest, config: config, bundle: bundle, root: trustedRoot, repository: d11Repository, reference: d11Repository + "@" + hashed(manifest)}
	approveImage(t, &m, expected, registrySPKI)
	var approval struct {
		Payload   []byte `json:"payload"`
		Signature []byte `json:"signature"`
	}
	d11Decode(t, m.approval, &approval)
	var payload map[string]any
	sourceRequire(t, json.Unmarshal(approval.Payload, &payload) == nil)
	payload["policyID"] = "d12-source-policy"
	approval.Payload = encode(t, payload)
	m.approval = encode(t, approval)
	managed := newManagedMaterial(t, m)
	document, anchor := managed.document, managed.anchor
	corpus := []sourceCatalogue{}
	valid := [][]byte{}
	for generation := uint64(1); generation <= 3; generation++ {
		document.Generation = generation
		raw := signManagedCatalogue(t, document, managed.rootKey)
		corpus = append(corpus, sourceCatalogue{fmt.Sprintf("g%d", generation), generation, raw, hashed(raw)})
		valid = append(valid, raw)
	}
	anchor.InitialSHA256 = corpus[0].SHA256
	replayed, err := trustcatalog.Replay(anchor, valid)
	sourceRequire(t, err == nil && replayed.ValidAt(time.Now()) && replayed.Generation() == 3)
	for index := 1; index <= 2; index++ {
		var envelope trustcatalog.Envelope
		d11Decode(t, valid[index], &envelope)
		sourceRequire(t, len(envelope.Signatures) == 1 && len(envelope.Signatures[0].Signature) == 64)
		envelope.Signatures[0].Signature[0] ^= 1
		raw := encode(t, envelope)
		corpus = append(corpus, sourceCatalogue{fmt.Sprintf("bad-g%d", index+1), uint64(index + 1), raw, hashed(raw)})
		_, invalid := trustcatalog.Replay(anchor, append(append([][]byte{}, valid[:index]...), raw))
		sourceRequire(t, invalid != nil)
	}
	policy := d11Policy{Name: "a", PolicyID: "d12-source-policy", GrantID: managed.document.Grants[0].ID,
		ApprovalSHA256: managed.trust.PolicySHA256, ApprovalEnvelopeSHA256: hashed(managed.approval),
		BundleSHA256: hashed(bundle), BundleArtifactSHA256: hashed(manifest), TrustedRootSHA256: hashed(trustedRoot), RegistrySPKI: registrySPKI}
	for name, raw := range map[string][]byte{"a-approval.private.json": managed.approval, "a-bundle.private.json": bundle,
		"trusted-root.private.json": trustedRoot, "anchor.json": encode(t, anchor)} {
		d11Write(t, filepath.Join(endpoint, name), raw)
	}
	for _, name := range []string{"api-ca.pem", "api-cert.pem", "api-key.private.pem", "registry-ca.pem", "source-ca.pem"} {
		d11Write(t, filepath.Join(endpoint, name), d11Read(t, filepath.Join(root, name), 256<<10))
	}
	for _, name := range []string{"api-ca.pem", "registry-ca.pem"} {
		sourceRequire(t, !bytes.Equal(d11Read(t, filepath.Join(endpoint, "source-ca.pem"), 256<<10), d11Read(t, filepath.Join(endpoint, name), 256<<10)))
	}
	for _, value := range corpus {
		d11Write(t, filepath.Join(sourceDirectory(root, flow, kind), "feed", "bodies", strings.TrimPrefix(value.SHA256, "sha256:")+".json"), value.Raw)
	}
	store, err := truststate.Create(context.Background(), filepath.Join(endpoint, "trust"), anchor, valid[0])
	sourceRequire(t, err == nil)
	inspection, err := store.Inspect(context.Background())
	sourceRequire(t, err == nil && inspection.Sequence == 1 && inspection.LedgerUsed == 0 && store.Close() == nil)
	audit, err := evidence.Open(filepath.Join(endpoint, "data", "evidence"))
	sourceRequire(t, err == nil && audit.Close() == nil)
	scope := d12Scope(anchor.StoreID)
	management := scope
	management.ObjectType, management.ObjectID = "control-plane", "d12-source-management"
	token, tokenHash, err := authn.GenerateToken(32)
	sourceRequire(t, err == nil)
	d11Write(t, filepath.Join(endpoint, "admin-token.private"), []byte(token))
	d11JSON(t, filepath.Join(endpoint, "identities.json"), authn.File{Version: authn.FileVersion, Identities: []authn.Identity{{TokenID: "d12-source-admin-token", TokenHash: tokenHash,
		Principal: authz.Principal{ID: "d12-source-admin", TenantID: scope.TenantID, Roles: []authz.Role{authz.RoleAdmin}, AllowedScopes: []authz.ResourceScope{scope, management}}}}})
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
	trustConfig["refreshSPKI"], trustConfig["refreshCAFile"] = feedSPKI, filepath.Join(endpoint, "source-ca.pem")
	trustConfig["refreshIntervalSeconds"], trustConfig["refreshMaxAgeSeconds"], trustConfig["refreshTimeoutSeconds"] = 2, 15, 2
	d11JSON(t, filepath.Join(endpoint, "trust-config.json"), trustConfig)
	common["dataDir"], common["managementObjectId"] = filepath.Join(endpoint, "data"), management.ObjectID
	d11JSON(t, filepath.Join(endpoint, "product-config.json"), common)
	info := sourceMaterial{d12Material: d12Material{d11Material: d11Material{Kind: kind, SourceCommit: commit, LocalImageID: imageID,
		ManifestSHA256: hashed(manifest), ConfigSHA256: hashed(config), LayerSHA256s: []string{}, DiffIDs: diffIDs,
		Catalogue1SHA256: corpus[0].SHA256, Catalogue2SHA256: corpus[1].SHA256, StoreID: anchor.StoreID, Anchor: anchor, Policies: []d11Policy{policy}},
		FeedURL: d12FeedURL, FeedSPKI: feedSPKI, FeedCASHA256: hashed(d11Read(t, filepath.Join(root, "source-ca.pem"), 256<<10)),
		RefreshIntervalSeconds: 2, RefreshMaxAgeSeconds: 15, RefreshTimeoutSeconds: 2}, AnchorRaw: encode(t, anchor), ApprovalRaw: managed.approval, Catalogues: corpus}
	for _, layer := range layers {
		info.LayerSHA256s = append(info.LayerSHA256s, hashed(layer))
	}
	d11JSON(t, filepath.Join(endpoint, "materials.private.json"), info)
	report := sourceNewReport(info, flow, "prepare")
	initial := "g1"
	if flow == "http-recovery" {
		initial = "forbidden"
	}
	report.FeedPlans = append(report.FeedPlans, sourcePublish(t, root, flow, kind, 1, initial, false, true, info))
	sourceSave(t, root, report)
}

// Concurrent appends are retried by the caller. Missing, replaced, insecure or
// malformed stable files never become an invented zero-event observation.
func sourceTryRaw(name string, limit int64, empty bool) ([]byte, bool) {
	fd, err := unix.Open(name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, false
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var before, after, named unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Mode&07777 != 0600 || before.Uid != 10001 || before.Gid != 10001 || before.Nlink != 1 || before.Size < 0 || before.Size > limit || !empty && before.Size == 0 {
		return nil, false
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(raw)) != before.Size || unix.Fstat(fd, &after) != nil || unix.Lstat(name, &named) != nil {
		return nil, false
	}
	identity := func(s unix.Stat_t) string {
		return fmt.Sprintf("%d/%d/%d/%d/%d/%d/%d/%v/%v", s.Dev, s.Ino, s.Mode, s.Uid, s.Gid, s.Nlink, s.Size, s.Mtim, s.Ctim)
	}
	return raw, identity(before) == identity(after) && identity(before) == identity(named)
}
func sourceRaw(t *testing.T, name string, limit int64, empty bool) []byte {
	t.Helper()
	raw, ok := sourceTryRaw(name, limit, empty)
	sourceRequire(t, ok)
	return raw
}
func sourceEvents(t *testing.T, ctx context.Context, root, flow, kind string) ([]sourceEvent, sourceFence) {
	t.Helper()
	path := filepath.Join(sourceDirectory(root, flow, kind), "feed", "events.jsonl")
	for ctx.Err() == nil {
		raw, ok := sourceTryRaw(path, 4<<20, true)
		if !ok || len(raw) > 0 && raw[len(raw)-1] != '\n' {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		events := []sourceEvent{}
		for _, line := range bytes.Split(bytes.TrimSuffix(raw, []byte{'\n'}), []byte{'\n'}) {
			if len(raw) == 0 {
				break
			}
			var event sourceEvent
			d11Decode(t, line, &event)
			sourceRequire(t, event.Schema == "chengwang.product-source-event/v1" && event.Ordinal == len(events)+1 && event.Connection >= 1 && event.Connection <= 512 && len(events) < 4096)
			sourceRequire(t, event.Event == "connect" || event.Event == "tls" || event.Event == "http" || event.Event == "close")
			events = append(events, event)
		}
		return events, sourceFence{len(events), strings.TrimPrefix(hashed(raw), "sha256:")}
	}
	sourceRequire(t, false)
	return nil, sourceFence{}
}
func sourceCount(events []sourceEvent, epoch int, mode, bodyHash string, after int) int {
	count := 0
	const forbiddenBody = "{\"code\":\"fixture_source_forbidden\"}\n"
	forbiddenHeaderBytes := len(fmt.Sprintf("HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: %d\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n", len(forbiddenBody)))
	for _, event := range events {
		if event.Event == "http" && event.Ordinal > after && event.Epoch == epoch && event.PathClass == "latest" && event.Generation == 0 && event.Mode == mode && event.Reason == "planned" && event.TLS && !event.AuthPresent {
			if mode == "forbidden" && event.Status == 403 && event.WrittenBytes >= forbiddenHeaderBytes || mode == "json" && event.Status == 200 && event.WireComplete && event.WrittenBytes == event.WireBytes && event.RepresentationSHA256 == strings.TrimPrefix(bodyHash, "sha256:") {
				count++
			}
		}
	}
	return count
}
func sourceWaitRequests(t *testing.T, ctx context.Context, root, flow, kind string, epoch int, mode, bodyHash string, after, minimum int) {
	t.Helper()
	for ctx.Err() == nil {
		events, _ := sourceEvents(t, ctx, root, flow, kind)
		if sourceCount(events, epoch, mode, bodyHash, after) >= minimum {
			return
		}
		time.Sleep(30 * time.Millisecond)
	}
	sourceRequire(t, false)
}

func sourceWaitGeneration2(t *testing.T, ctx context.Context, root, flow, kind, bodyHash string) {
	t.Helper()
	for ctx.Err() == nil {
		events, _ := sourceEvents(t, ctx, root, flow, kind)
		for _, event := range events {
			if event.Event == "http" && event.Epoch == 2 && event.PathClass == "generation" && event.Generation == 2 && event.Mode == "json" && event.Reason == "planned" && event.Status == 200 && event.TLS && !event.AuthPresent && event.WireComplete && event.WrittenBytes == event.WireBytes && event.RepresentationSHA256 == strings.TrimPrefix(bodyHash, "sha256:") {
				return
			}
		}
		time.Sleep(30 * time.Millisecond)
	}
	sourceRequire(t, false)
}

func sourceSnapshot(t *testing.T, ctx context.Context, client *http.Client, kind, token string) (imagetrust.Status, imagetrust.History) {
	t.Helper()
	for ctx.Err() == nil {
		var status, after imagetrust.Status
		if !d12ReadAPI(t, ctx, client, d11APIBase(kind)+"/api/v1/image-trust", token, &status) {
			time.Sleep(30 * time.Millisecond)
			continue
		}
		history := imagetrust.History{Entries: []imagetrust.HistoryEntry{}}
		seen := map[string]bool{}
		complete := true
		for offset := 0; ; {
			var page imagetrust.History
			target := fmt.Sprintf("%s/api/v1/image-trust/history?limit=50&offset=%d&sequence=%d", d11APIBase(kind), offset, status.Sequence)
			if !d12ReadAPI(t, ctx, client, target, token, &page) {
				complete = false
				break
			}
			sourceRequire(t, page.Boundary == imagetrust.HistoryBoundary && page.Authorization == "BLOCKED" && !page.DeviceActionsExecuted && page.Offset == offset && page.Limit == 50 && len(page.Entries) <= 50 && page.Total >= 0 && page.Total <= truststate.MaxOperations)
			if page.Sequence != status.Sequence || offset > 0 && page.Total != history.Total {
				complete = false
				break
			}
			if offset == 0 {
				history = page
				history.Entries = []imagetrust.HistoryEntry{}
			}
			for _, entry := range page.Entries {
				sourceRequire(t, entry.OperationID != "" && !seen[entry.OperationID])
				seen[entry.OperationID] = true
				if !entry.Acknowledged || len(entry.PreparedAuditHash) != 64 || len(entry.ResultAuditHash) != 64 {
					complete = false
					break
				}
				history.Entries = append(history.Entries, entry)
			}
			if !complete {
				break
			}
			offset += len(page.Entries)
			if offset == page.Total {
				break
			}
			sourceRequire(t, len(page.Entries) == 50 && offset < page.Total)
		}
		if complete && d12ReadAPI(t, ctx, client, d11APIBase(kind)+"/api/v1/image-trust", token, &after) && after.Sequence == status.Sequence && history.Total == len(history.Entries) {
			sourceRequire(t, after.Boundary == imagetrust.StatusBoundary && after.Authorization == "BLOCKED" && !after.DeviceActionsExecuted && after.Healthy && after.Fresh && after.RefreshRequired && after.RecoveryCompleted == 0 && after.NotAfterUnix > time.Now().Unix())
			return after, history
		}
		time.Sleep(30 * time.Millisecond)
	}
	sourceRequire(t, false)
	return imagetrust.Status{}, imagetrust.History{}
}
func sourceState(info sourceMaterial, status imagetrust.Status, history imagetrust.History, sequence, generation uint64, operations int) bool {
	if status.Sequence != sequence || status.Generation != generation || history.Sequence != sequence || history.Total != operations {
		return false
	}
	if status.StoreID != info.StoreID || status.LedgerEntries != 0 || status.Reserved != 0 || status.Consumed != 0 || status.RevokedKeys != 0 || status.RevokedApprovals != 0 || status.RevokedManifests != 0 || len(status.Policies) != 1 || status.Policies[0].State != "AVAILABLE" || status.Policies[0].PolicyID != "d12-source-policy" {
		return false
	}
	for _, catalogue := range info.Catalogues {
		if catalogue.Name == fmt.Sprintf("g%d", generation) {
			return status.CatalogueSHA256 == catalogue.SHA256
		}
	}
	return false
}
func sourceObserve(t *testing.T, ctx context.Context, client *http.Client, root, flow, kind, token, name string) sourceObservation {
	t.Helper()
	status, history := sourceSnapshot(t, ctx, client, kind, token)
	_, fence := sourceEvents(t, ctx, root, flow, kind)
	return sourceObservation{Name: name, Status: status, History: history, SourceFence: fence}
}
func sourceWaitState(t *testing.T, ctx context.Context, client *http.Client, root, flow, kind, token, name string, info sourceMaterial, seq, gen uint64, operations int, predicate func(imagetrust.Status) bool) sourceObservation {
	t.Helper()
	for ctx.Err() == nil {
		observation := sourceObserve(t, ctx, client, root, flow, kind, token, name)
		if sourceState(info, observation.Status, observation.History, seq, gen, operations) && predicate(observation.Status) {
			return observation
		}
		time.Sleep(40 * time.Millisecond)
	}
	sourceRequire(t, false)
	return sourceObservation{}
}
func sourceSameFresh(left, right imagetrust.Status) bool {
	return left.RefreshLastSuccessUnix == right.RefreshLastSuccessUnix && left.RefreshUntilUnix == right.RefreshUntilUnix
}
func sourceSameDomain(left, right sourceObservation) bool {
	return d12SameDomain(left.Status, right.Status, left.History, right.History)
}
func sourceRun(t *testing.T, root, flow, kind, commit, imageID string) {
	t.Helper()
	prepared := sourceLoad(t, root, flow, kind, "prepare")
	info := prepared.Material
	sourceRequire(t, info.SourceCommit == commit && info.LocalImageID == imageID)
	report := sourceNewReport(info, flow, "run")
	client := d11Client(t, root, false)
	token := string(d11Read(t, filepath.Join(sourceEndpoint(root, flow, kind), "admin-token.private"), 4096))
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	fresh := func(status imagetrust.Status) bool {
		return status.RefreshFresh && status.RefreshLastSuccessUnix > 0 && status.RefreshUntilUnix > status.ObservedAtUnix
	}
	anyFresh := func(imagetrust.Status) bool { return true }
	g1 := sourceCatalogueNamed(t, info, "g1")
	if flow == "http-recovery" {
		sourceWaitRequests(t, ctx, root, flow, kind, 1, "forbidden", "", 0, 2)
		initial := sourceObserve(t, ctx, client, root, flow, kind, token, "unconfirmed")
		sourceRequire(t, sourceState(info, initial.Status, initial.History, 1, 1, 0) && !initial.Status.RefreshFresh && initial.Status.RefreshLastSuccessUnix == 0 && initial.Status.RefreshUntilUnix == 0)
		report.Observations = append(report.Observations, initial)
		report.FeedPlans = append(report.FeedPlans, sourcePublish(t, root, flow, kind, 2, "g1", false, false, info))
		sourceWaitRequests(t, ctx, root, flow, kind, 2, "json", g1.SHA256, 0, 1)
		confirmed := sourceWaitState(t, ctx, client, root, flow, kind, token, "confirmed", info, 1, 1, 0, fresh)
		report.Observations = append(report.Observations, confirmed)
		report.FeedPlans = append(report.FeedPlans, sourcePublish(t, root, flow, kind, 3, "forbidden", false, false, info))
		// Two successor callbacks fence any old G1 response/confirmation. Only
		// then is the last successful refresh a stable stale-phase baseline.
		sourceWaitRequests(t, ctx, root, flow, kind, 3, "forbidden", "", 0, 2)
		forbidden := sourceObserve(t, ctx, client, root, flow, kind, token, "forbidden")
		sourceRequire(t, sourceSameDomain(confirmed, forbidden) && forbidden.Status.RefreshLastSuccessUnix >= confirmed.Status.RefreshLastSuccessUnix && forbidden.Status.RefreshUntilUnix > 0)
		report.Observations = append(report.Observations, forbidden)
		stale := sourceWaitState(t, ctx, client, root, flow, kind, token, "stale", info, 1, 1, 0, func(status imagetrust.Status) bool {
			return !status.RefreshFresh && status.ObservedAtUnix > forbidden.Status.RefreshUntilUnix
		})
		sourceRequire(t, sourceSameDomain(forbidden, stale) && sourceSameFresh(forbidden.Status, stale.Status))
		report.Observations = append(report.Observations, stale)
		report.FeedPlans = append(report.FeedPlans, sourcePublish(t, root, flow, kind, 4, "g1", false, false, info))
		sourceWaitRequests(t, ctx, root, flow, kind, 4, "json", g1.SHA256, 0, 1)
		recovered := sourceWaitState(t, ctx, client, root, flow, kind, token, "recovered", info, 1, 1, 0, func(status imagetrust.Status) bool {
			return fresh(status) && status.RefreshLastSuccessUnix > stale.Status.RefreshLastSuccessUnix && status.RefreshUntilUnix > stale.Status.RefreshUntilUnix
		})
		sourceRequire(t, sourceSameDomain(stale, recovered))
		report.Observations = append(report.Observations, recovered)
	} else {
		sourceWaitRequests(t, ctx, root, flow, kind, 1, "json", g1.SHA256, 0, 1)
		confirmed := sourceWaitState(t, ctx, client, root, flow, kind, token, "confirmed", info, 1, 1, 0, fresh)
		report.Observations = append(report.Observations, confirmed)
		badName, rejectedName, gen, seq, operations := "bad-g2", "rejected", uint64(1), uint64(5), 1
		if flow == "prefix-recovery" {
			badName, rejectedName, gen, seq, operations = "bad-g3", "prefix-rejected", 2, 9, 2
		}
		bad := sourceCatalogueNamed(t, info, badName)
		report.FeedPlans = append(report.FeedPlans, sourcePublish(t, root, flow, kind, 2, badName, flow == "prefix-recovery", false, info))
		// The client can finish parsing before the source thread appends its
		// send event. Observe the actual causal response before taking API/fence
		// evidence; a later sourceFence must include this completed HTTP event.
		sourceWaitRequests(t, ctx, root, flow, kind, 2, "json", bad.SHA256, 0, 1)
		if flow == "prefix-recovery" {
			sourceWaitGeneration2(t, ctx, root, flow, kind, sourceCatalogueNamed(t, info, "g2").SHA256)
		}
		rejected := sourceWaitState(t, ctx, client, root, flow, kind, token, rejectedName, info, seq, gen, operations, anyFresh)
		sourceRequire(t, rejected.Status.RefreshLastSuccessUnix >= confirmed.Status.RefreshLastSuccessUnix && rejected.Status.RefreshUntilUnix > 0)
		lastEntry := rejected.History.Entries[len(rejected.History.Entries)-1]
		sourceRequire(t, lastEntry.ActorID == "image-trust-refresh" && lastEntry.Kind == "update" && lastEntry.Outcome == truststate.OutcomeRejected && lastEntry.Acknowledged)
		if flow == "prefix-recovery" {
			sourceRequire(t, !rejected.Status.RefreshFresh && rejected.History.Entries[0].Outcome == truststate.OutcomeCatalogueCommitted)
		}
		report.Observations = append(report.Observations, rejected)
		sourceWaitRequests(t, ctx, root, flow, kind, 2, "json", bad.SHA256, rejected.SourceFence.EventCount, 3)
		dedup := sourceObserve(t, ctx, client, root, flow, kind, token, "deduplicated")
		sourceRequire(t, sourceSameDomain(rejected, dedup) && sourceSameFresh(rejected.Status, dedup.Status))
		report.Observations = append(report.Observations, dedup)
		if flow == "bad-signature" {
			stale := sourceWaitState(t, ctx, client, root, flow, kind, token, "stale", info, seq, gen, operations, func(status imagetrust.Status) bool {
				return !status.RefreshFresh && status.ObservedAtUnix > rejected.Status.RefreshUntilUnix
			})
			sourceRequire(t, sourceSameDomain(rejected, stale) && sourceSameFresh(rejected.Status, stale.Status))
			report.Observations = append(report.Observations, stale)
		}
		validName, finalSeq, finalGen, finalOperations := "g2", uint64(9), uint64(2), 2
		if flow == "prefix-recovery" {
			validName, finalSeq, finalGen, finalOperations = "g3", 13, 3, 3
		}
		report.FeedPlans = append(report.FeedPlans, sourcePublish(t, root, flow, kind, 3, validName, false, false, info))
		sourceWaitRequests(t, ctx, root, flow, kind, 3, "json", sourceCatalogueNamed(t, info, validName).SHA256, 0, 1)
		recovered := sourceWaitState(t, ctx, client, root, flow, kind, token, "recovered", info, finalSeq, finalGen, finalOperations, func(status imagetrust.Status) bool {
			return fresh(status) && status.RefreshLastSuccessUnix > rejected.Status.RefreshLastSuccessUnix
		})
		report.Observations = append(report.Observations, recovered)
	}
	sourceSave(t, root, report)
}

func sourceRecordHash(t *testing.T, endpoint string) string {
	t.Helper()
	path := filepath.Join(endpoint, "trust", "trust.db")
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	sourceRequire(t, err == nil)
	defer unix.Close(fd)
	var before, after unix.Stat_t
	sourceRequire(t, unix.Fstat(fd, &before) == nil && before.Mode&unix.S_IFMT == unix.S_IFREG && before.Mode&07777 == 0600 && before.Uid == 10001 && before.Gid == 10001 && before.Nlink == 1 && before.Size > 0 && before.Size <= 64<<20)
	db, err := bolt.Open(fmt.Sprintf("/proc/self/fd/%d", fd), 0600, &bolt.Options{ReadOnly: true, Timeout: time.Second})
	sourceRequire(t, err == nil)
	var digest string
	err = db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("trusted-state-v1"))
		if bucket == nil {
			return errors.New("fixture record missing")
		}
		raw := bucket.Get([]byte("state"))
		if len(raw) == 0 || len(raw) > 8<<20 {
			return errors.New("fixture record invalid")
		}
		digest = strings.TrimPrefix(hashed(raw), "sha256:")
		return nil
	})
	sourceRequire(t, err == nil && db.Close() == nil && unix.Fstat(fd, &after) == nil && before.Dev == after.Dev && before.Ino == after.Ino && before.Size == after.Size && before.Mtim == after.Mtim && before.Ctim == after.Ctim)
	return digest
}
func sourceReopen(t *testing.T, root, flow, kind, commit, imageID string) {
	t.Helper()
	previous := sourceLoad(t, root, flow, kind, "run")
	prepared := sourceLoad(t, root, flow, kind, "prepare")
	info := previous.Material
	sourceRequire(t, info.SourceCommit == commit && info.LocalImageID == imageID && reflect.DeepEqual(info, prepared.Material) && len(previous.Observations) > 0)
	last := previous.Observations[len(previous.Observations)-1]
	sequence, generation, operations := uint64(1), uint64(1), 0
	if flow == "bad-signature" {
		sequence, generation, operations = 9, 2, 2
	}
	if flow == "prefix-recovery" {
		sequence, generation, operations = 13, 3, 3
	}
	sourceRequire(t, sourceState(info, last.Status, last.History, sequence, generation, operations) && last.Status.RefreshFresh)
	endpoint := sourceEndpoint(root, flow, kind)
	logPath := filepath.Join(endpoint, "data", "evidence", "events.jsonl")
	cpPath := filepath.Join(endpoint, "data", "evidence", "checkpoint.json")
	logBefore, cpBefore := sourceRaw(t, logPath, 4<<20, true), sourceRaw(t, cpPath, 8<<10, false)
	recordBefore := sourceRecordHash(t, endpoint)
	// No product constructor, recovery hook, checkpoint repair or database
	// mutation: these are the actual public Store/Audit readers after stop.
	store, err := truststate.Open(context.Background(), filepath.Join(endpoint, "trust"), info.Anchor)
	sourceRequire(t, err == nil)
	defer store.Close()
	inspection, err := store.Inspect(context.Background())
	sourceRequire(t, err == nil && inspection.Authorization == "BLOCKED" && inspection.CatalogueValid && inspection.Sequence == sequence && inspection.Catalogue.Generation == generation && inspection.Catalogue.SHA256 == last.Status.CatalogueSHA256 && inspection.LedgerUsed == 0 && len(inspection.Consumptions) == 0)
	journal, err := store.Journal(context.Background())
	sourceRequire(t, err == nil && len(journal) == operations)
	if journal == nil {
		journal = []truststate.JournalEntry{}
	}
	audit, err := evidence.Open(filepath.Join(endpoint, "data", "evidence"))
	sourceRequire(t, err == nil)
	defer audit.Close()
	proof, err := audit.Verify()
	sourceRequire(t, err == nil && proof.Valid && proof.Issue == "" && proof.Count == uint64(operations*2) && proof.Count == proof.ExpectedCount && proof.LastHash == proof.ExpectedLastHash)
	view, err := audit.RecoverySnapshot()
	sourceRequire(t, err == nil)
	events := []evidence.EvidenceEvent{}
	if len(logBefore) > 0 {
		sourceRequire(t, logBefore[len(logBefore)-1] == '\n')
		for _, raw := range bytes.Split(bytes.TrimSuffix(logBefore, []byte{'\n'}), []byte{'\n'}) {
			var event evidence.EvidenceEvent
			d11Decode(t, raw, &event)
			events = append(events, event)
		}
	}
	sourceRequire(t, len(events) == operations*2)
	bindings := []d12AuditBinding{}
	names := []string{}
	if flow == "bad-signature" {
		names = []string{"bad-g2", "g2"}
	}
	if flow == "prefix-recovery" {
		names = []string{"g2", "bad-g3", "g3"}
	}
	for index, entry := range journal {
		candidate := sourceCatalogueNamed(t, info, names[index])
		rejected := strings.HasPrefix(names[index], "bad-")
		outcome, result := truststate.OutcomeCatalogueCommitted, "completed"
		if rejected {
			outcome, result = truststate.OutcomeRejected, "rejected"
		}
		sourceRequire(t, entry.Operation.ActorID == "image-trust-refresh" && entry.Operation.Kind == "update" && entry.Operation.ScopeSHA256 == hashed(encode(t, d12Scope(info.StoreID))) && entry.Outcome == outcome && entry.Acknowledged)
		sourceRequire(t, d11SameData(entry.Operation.Data, map[string]string{"catalogueSHA256": candidate.SHA256}))
		base, ok := view.HashAt(entry.Operation.AuditBaseCount)
		sourceRequire(t, ok && base == entry.Operation.AuditBaseHash)
		preparedEvent, ok := view.Lookup("image-trust/" + entry.Operation.ID + "/prepared")
		sourceRequire(t, ok)
		resultEvent, ok := view.Lookup("image-trust/" + entry.Operation.ID + "/result")
		sourceRequire(t, ok)
		sourceRequire(t, preparedEvent.Hash == entry.Operation.PreparedAuditHash && resultEvent.Hash == entry.ResultAuditHash && preparedEvent.ActorID == entry.Operation.ActorID && resultEvent.ActorID == entry.Operation.ActorID && preparedEvent.TraceID == entry.Operation.ID && resultEvent.TraceID == entry.Operation.ID)
		sourceRequire(t, preparedEvent.Action == "image_trust.update" && resultEvent.Action == preparedEvent.Action && preparedEvent.Target == "image-trust/"+info.StoreID && resultEvent.Target == preparedEvent.Target && preparedEvent.Result == "prepared" && resultEvent.Result == result)
		sourceRequire(t, d11SameData(preparedEvent.Data, entry.Operation.Data) && d11SameData(resultEvent.Data, entry.OutcomeData) && entry.GrantID == "" && entry.ManifestSHA256 == "" && entry.EvidenceSHA256 == "")
		if rejected {
			sourceRequire(t, entry.State == "PREPARED" && entry.Generation == 0 && entry.CatalogueSHA256 == "" && len(entry.OutcomeData) == 0)
		} else {
			sourceRequire(t, entry.State == "COMMITTED" && entry.Generation == candidate.Generation && entry.CatalogueSHA256 == candidate.SHA256 && d11SameData(entry.OutcomeData, map[string]string{"catalogueSHA256": candidate.SHA256}))
		}
		found := false
		for _, historical := range last.History.Entries {
			if historical.OperationID == entry.Operation.ID {
				sourceRequire(t, historical.ActorID == entry.Operation.ActorID && historical.Kind == entry.Operation.Kind && historical.State == entry.State && historical.Outcome == entry.Outcome && historical.Acknowledged && historical.PreparedAuditHash == preparedEvent.Hash && historical.ResultAuditHash == resultEvent.Hash)
				found = true
			}
		}
		sourceRequire(t, found)
		bindings = append(bindings, d12AuditBinding{OperationID: entry.Operation.ID, Prepared: preparedEvent, Result: resultEvent})
	}
	sourceRequire(t, store.Close() == nil && audit.Close() == nil)
	logAfter, cpAfter := sourceRaw(t, logPath, 4<<20, true), sourceRaw(t, cpPath, 8<<10, false)
	recordAfter := sourceRecordHash(t, endpoint)
	sourceRequire(t, bytes.Equal(logBefore, logAfter) && bytes.Equal(cpBefore, cpAfter) && recordBefore == recordAfter)
	report := sourceNewReport(info, flow, "reopen")
	report.Offline = &sourceOffline{Inspection: inspection, Journal: journal, Audit: proof, AuditEvents: events, AuditBindings: bindings,
		AuditLog: sourceRawDigest(logBefore), Checkpoint: sourceRawDigest(cpBefore), TrustRecordSHA256: recordBefore}
	sourceSave(t, root, report)
}
