//go:build linux && productregistry && productcrash

package binding_test

// This client/offline inspector has no product backend or fault hook. Only the
// separately inspected image process performs recovery or managed verification.
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
	"syscall"
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

const crashBoundary = "ADVISORY_PRODUCT_CRASH_FIXTURE"

type crashMaterial struct {
	Kind            string              `json:"kind"`
	SourceCommit    string              `json:"sourceCommit"`
	LocalImageID    string              `json:"localImageID"`
	ManifestSHA256  string              `json:"manifestSHA256"`
	ConfigSHA256    string              `json:"configSHA256"`
	LayerSHA256s    []string            `json:"layerSHA256s"`
	DiffIDs         []string            `json:"diffIDs"`
	CatalogueSHA256 string              `json:"catalogueSHA256"`
	StoreID         string              `json:"storeID"`
	Policies        []d11Policy         `json:"policies"`
	Anchor          trustcatalog.Anchor `json:"-"`
}

type crashRawHash struct {
	Bytes  int    `json:"bytes"`
	SHA256 string `json:"sha256"`
}

type crashAuditBinding struct {
	OperationID string                  `json:"operationID"`
	Prepared    *evidence.EvidenceEvent `json:"prepared"`
	Result      *evidence.EvidenceEvent `json:"result"`
}

type crashRequest struct {
	Method                 string `json:"method"`
	Path                   string `json:"path"`
	PolicyID               string `json:"policyID"`
	GrantID                string `json:"grantID"`
	ApprovalSHA256         string `json:"approvalSHA256"`
	ApprovalEnvelopeSHA256 string `json:"approvalEnvelopeSHA256"`
	BundleSHA256           string `json:"bundleSHA256"`
	TrustedRootSHA256      string `json:"trustedRootSHA256"`
	RequestSHA256          string `json:"requestSHA256"`
	Attempts               int    `json:"attempts"`
	HTTPStatus             int    `json:"httpStatus"`
	TransportOutcome       string `json:"transportOutcome"`
}

type crashReport struct {
	Schema string `json:"schema"`
	Action string `json:"action"`
	Stage  string `json:"stage"`
	crashMaterial
	Boundary              string                    `json:"boundary"`
	Authority             string                    `json:"authority"`
	GraphOrigin           string                    `json:"graphOrigin"`
	Authorization         string                    `json:"authorization"`
	Production            bool                      `json:"production"`
	DeviceActionsExecuted bool                      `json:"deviceActionsExecuted"`
	Cases                 []d11Case                 `json:"cases"`
	Status                *imagetrust.Status        `json:"status,omitempty"`
	History               *imagetrust.History       `json:"history,omitempty"`
	Request               *crashRequest             `json:"request,omitempty"`
	Inspection            *truststate.Inspection    `json:"inspection,omitempty"`
	Journal               []truststate.JournalEntry `json:"journal,omitempty"`
	Audit                 *evidence.VerifyReport    `json:"audit,omitempty"`
	AuditBindings         []crashAuditBinding       `json:"auditBindings,omitempty"`
	AuditLog              *crashRawHash             `json:"auditLog,omitempty"`
	Checkpoint            *crashRawHash             `json:"checkpoint,omitempty"`
}

func crashRequire(t *testing.T, ok bool) {
	t.Helper()
	if !ok {
		_, own, _, _ := runtime.Caller(0)
		if _, file, line, found := runtime.Caller(1); found && file == own {
			fmt.Printf("D12_PRODUCT_CRASH_ASSERT_LINE=%d\n", line)
		}
		t.Fatal("isolated product interruption fixture rejected")
	}
}

func crashEndpoint(root, stage, kind string) string { return filepath.Join(root, stage, kind) }
func crashReportPath(root, stage, kind, action string) string {
	return filepath.Join(root, "evidence", "product-crash-"+stage+"-"+kind+"-"+action+".json")
}
func crashNew(info crashMaterial, stage, action string) crashReport {
	return crashReport{Schema: "chengwang.product-crash-action/v1", Action: action, Stage: stage,
		crashMaterial: info, Boundary: crashBoundary, Authority: "EPHEMERAL_TEST_ONLY",
		GraphOrigin: "NORMAL_TLS_REGISTRY_READBACK_MATCHED_UPLOAD", Authorization: "BLOCKED", Cases: []d11Case{}}
}
func crashSave(t *testing.T, root string, report crashReport) {
	t.Helper()
	d11Dir(t, filepath.Join(root, "evidence"))
	d11JSON(t, crashReportPath(root, report.Stage, report.Kind, report.Action), report)
}
func crashLoad(t *testing.T, root, stage, kind, action string) crashReport {
	t.Helper()
	var report crashReport
	d11Decode(t, d11Read(t, crashReportPath(root, stage, kind, action), 4<<20), &report)
	crashRequire(t, report.Schema == "chengwang.product-crash-action/v1" && report.Action == action && report.Stage == stage && report.Kind == kind && report.Boundary == crashBoundary && report.Authority == "EPHEMERAL_TEST_ONLY" && report.Authorization == "BLOCKED" && !report.Production && !report.DeviceActionsExecuted)
	return report
}

func TestProductCrashD12Fixture(t *testing.T) {
	root, stage, kind := os.Getenv("CHENGWANG_CRASH_ROOT"), os.Getenv("CHENGWANG_CRASH_STAGE"), os.Getenv("CHENGWANG_CRASH_KIND")
	commit, image := os.Getenv("CHENGWANG_CRASH_COMMIT"), os.Getenv("CHENGWANG_CRASH_IMAGE_ID")
	crashRequire(t, os.Getuid() == 10001 && os.Geteuid() == 10001 && os.Getgid() == 10001 && os.Getegid() == 10001)
	crashRequire(t, regexp.MustCompile(`^/tmp/chengwang-product-lifecycle-[0-9a-f]{32}$`).MatchString(root))
	crashRequire(t, (stage == "prepared" || stage == "reserved" || stage == "consumed") && (kind == "message-signature" || kind == "dsse"))
	crashRequire(t, regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(commit) && regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(image))
	d11Dir(t, root)
	d11Dir(t, filepath.Join(root, stage))
	crashRequire(t, string(d11Read(t, filepath.Join(root, ".fixture-owner"), 64)) == strings.TrimPrefix(root, "/tmp/chengwang-product-lifecycle-")+"\n")
	crashRequire(t, os.Getenv("CHENGWANG_CRASH_ARCHIVE") == filepath.Join(root, "bin", "product-image.private.tar"))
	t.Setenv("CHENGWANG_D11_KIND", kind)
	t.Setenv("CHENGWANG_D11_ARCHIVE", os.Getenv("CHENGWANG_CRASH_ARCHIVE"))
	action := os.Getenv("CHENGWANG_CRASH_ACTION")
	if action == "prepare" {
		crashPrepare(t, root, stage, kind, commit, image)
	} else {
		info := crashInfo(t, root, stage, kind, commit, image)
		switch action {
		case "ready", "recovered", "idempotent":
			crashObserve(t, root, stage, action, info)
		case "send":
			crashSend(t, root, stage, info)
		case "blocked", "reserved":
			crashBlocked(t, root, stage, action, info)
		case "cut", "reopen-first", "reopen-final":
			crashReopen(t, root, stage, action, info)
		case "probe":
			crashProbe(t, root, stage, info)
		default:
			crashRequire(t, false)
		}
	}
	fmt.Printf("D12_PRODUCT_CRASH_%s=PASS stage=%s kind=%s authorization=BLOCKED production=false\n", strings.ReplaceAll(strings.ToUpper(action), "-", "_"), stage, kind)
}

func crashScope(store string) authz.ResourceScope {
	return authz.ResourceScope{TenantID: "d12-tenant", SiteID: "d12-site", ObjectType: "image-trust", ObjectID: store, Environment: "candidate"}
}
func crashPort(kind string) string {
	if kind == "dsse" {
		return "17832"
	}
	return "17831"
}
func crashAPI(kind string) string { return "https://api.fixture.invalid:" + crashPort(kind) }

func crashPrepare(t *testing.T, root, stage, kind, commit, image string) {
	t.Helper()
	endpoint := crashEndpoint(root, stage, kind)
	d11Mkdir(t, endpoint)
	d11Mkdir(t, filepath.Join(endpoint, "data"))
	manifest, config, layers, diffs := d11Archive(t, root, commit, image)
	d11Upload(t, root, endpoint, manifest, config, layers)
	leaf, _ := pem.Decode(d11Read(t, filepath.Join(root, "registry-cert.pem"), 256<<10))
	crashRequire(t, leaf != nil)
	certificate, err := x509.ParseCertificate(leaf.Bytes)
	crashRequire(t, err == nil && certificate.VerifyHostname("registry.fixture.invalid") == nil)
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
	crashRequire(t, json.Unmarshal(envelope.Payload, &approval) == nil)
	approval["policyID"] = "d12-crash-" + stage
	// The changed unsigned template is reissued by a fresh ephemeral authority.
	envelope.Payload = encode(t, approval)
	m.approval = encode(t, envelope)
	managed := newManagedMaterial(t, m)
	policy := d11Policy{Name: "original", PolicyID: "d12-crash-" + stage, GrantID: managed.document.Grants[0].ID,
		ApprovalSHA256: managed.trust.PolicySHA256, ApprovalEnvelopeSHA256: hashed(managed.approval),
		BundleSHA256: hashed(bundle), BundleArtifactSHA256: hashed(manifest), TrustedRootSHA256: hashed(trustedRoot), RegistrySPKI: spki}
	d11Write(t, filepath.Join(endpoint, "original-approval.private.json"), managed.approval)
	d11Write(t, filepath.Join(endpoint, "original-bundle.private.json"), bundle)
	d11Write(t, filepath.Join(endpoint, "trusted-root.private.json"), trustedRoot)
	d11Write(t, filepath.Join(endpoint, "catalogue.private.json"), managed.catalogue)
	d11JSON(t, filepath.Join(endpoint, "anchor.json"), managed.anchor)
	for _, name := range []string{"api-ca.pem", "api-cert.pem", "api-key.private.pem", "registry-ca.pem"} {
		d11Write(t, filepath.Join(endpoint, name), d11Read(t, filepath.Join(root, name), 256<<10))
	}
	store, err := truststate.Create(context.Background(), filepath.Join(endpoint, "trust"), managed.anchor, managed.catalogue)
	crashRequire(t, err == nil)
	inspection, err := store.Inspect(context.Background())
	crashRequire(t, err == nil && inspection.Sequence == 1 && inspection.LedgerUsed == 0 && store.Close() == nil)
	audit, err := evidence.Open(filepath.Join(endpoint, "data", "evidence"))
	crashRequire(t, err == nil && audit.Close() == nil)
	scope := crashScope(managed.anchor.StoreID)
	management := scope
	management.ObjectType, management.ObjectID = "control-plane", "d12-crash-management"
	token, tokenHash, err := authn.GenerateToken(32)
	crashRequire(t, err == nil)
	d11Write(t, filepath.Join(endpoint, "admin-token.private"), []byte(token))
	d11JSON(t, filepath.Join(endpoint, "identities.json"), authn.File{Version: authn.FileVersion, Identities: []authn.Identity{{
		TokenID: "d12-crash-admin-token", TokenHash: tokenHash, Principal: authz.Principal{ID: "d12-crash-admin", TenantID: scope.TenantID, Roles: []authz.Role{authz.RoleAdmin}, AllowedScopes: []authz.ResourceScope{scope, management}}}}})
	common := map[string]any{"addr": "127.0.0.1:" + crashPort(kind), "identitiesFile": filepath.Join(endpoint, "identities.json"),
		"tlsCertFile": filepath.Join(endpoint, "api-cert.pem"), "tlsKeyFile": filepath.Join(endpoint, "api-key.private.pem"),
		"tenantId": scope.TenantID, "siteId": scope.SiteID, "environment": "candidate"}
	trustConfig := map[string]any{}
	for key, value := range common {
		trustConfig[key] = value
	}
	trustConfig["storePath"], trustConfig["anchorFile"] = filepath.Join(endpoint, "trust"), filepath.Join(endpoint, "anchor.json")
	trustConfig["auditDir"], trustConfig["registryCAFile"] = filepath.Join(endpoint, "data", "evidence"), filepath.Join(endpoint, "registry-ca.pem")
	trustConfig["writesEnabled"], trustConfig["webDir"] = true, "/app/web"
	// This separate interruption matrix uses the existing static catalogue mode;
	// the earlier actual automatic-refresh gate remains entirely unchanged.
	d11JSON(t, filepath.Join(endpoint, "trust-config.json"), trustConfig)
	common["dataDir"], common["managementObjectId"] = filepath.Join(endpoint, "data"), management.ObjectID
	d11JSON(t, filepath.Join(endpoint, "product-config.json"), common)
	info := crashMaterial{Kind: kind, SourceCommit: commit, LocalImageID: image, ManifestSHA256: hashed(manifest), ConfigSHA256: hashed(config),
		LayerSHA256s: []string{}, DiffIDs: diffs, CatalogueSHA256: hashed(managed.catalogue), StoreID: managed.anchor.StoreID, Policies: []d11Policy{policy}, Anchor: managed.anchor}
	for _, layer := range layers {
		info.LayerSHA256s = append(info.LayerSHA256s, hashed(layer))
	}
	d11JSON(t, filepath.Join(endpoint, "materials.private.json"), info)
	crashSave(t, root, crashNew(info, stage, "prepare"))
}

func crashInfo(t *testing.T, root, stage, kind, commit, image string) crashMaterial {
	t.Helper()
	var info crashMaterial
	endpoint := crashEndpoint(root, stage, kind)
	d11Decode(t, d11Read(t, filepath.Join(endpoint, "materials.private.json"), 256<<10), &info)
	d11Decode(t, d11Read(t, filepath.Join(endpoint, "anchor.json"), 8<<10), &info.Anchor)
	crashRequire(t, info.Kind == kind && info.SourceCommit == commit && info.LocalImageID == image && info.ConfigSHA256 == image && len(info.Policies) == 1 && reflect.DeepEqual(info.LayerSHA256s, info.DiffIDs))
	crashRequire(t, info.StoreID == info.Anchor.StoreID && info.CatalogueSHA256 == info.Anchor.InitialSHA256)
	policy := info.Policies[0]
	crashRequire(t, policy.Name == "original" && policy.PolicyID == "d12-crash-"+stage && policy.BundleArtifactSHA256 == info.ManifestSHA256)
	return info
}

func crashClient(t *testing.T, root, kind string) *http.Client {
	t.Helper()
	roots := x509.NewCertPool()
	crashRequire(t, roots.AppendCertsFromPEM(d11Read(t, filepath.Join(root, "api-ca.pem"), 256<<10)))
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, ForceAttemptHTTP2: false,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: "api.fixture.invalid", NextProtos: []string{"http/1.1"}},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != net.JoinHostPort("api.fixture.invalid", crashPort(kind)) {
				return nil, errors.New("fixture destination rejected")
			}
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", crashPort(kind)))
		}}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 90 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func crashToken(t *testing.T, root, stage, kind string) string {
	t.Helper()
	return string(d11Read(t, filepath.Join(crashEndpoint(root, stage, kind), "admin-token.private"), 512))
}

func crashGet(t *testing.T, ctx context.Context, client *http.Client, target, token string, destination any) bool {
	t.Helper()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	crashRequire(t, err == nil)
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
	crashRequire(t, response.StatusCode == 200 && len(raw) <= 4<<20)
	d11Decode(t, raw, destination)
	return true
}

func crashStatusBoundary(t *testing.T, status imagetrust.Status, info crashMaterial) {
	t.Helper()
	crashRequire(t, status.Boundary == imagetrust.StatusBoundary && status.Authorization == "BLOCKED" && !status.DeviceActionsExecuted && status.Healthy && status.Fresh && !status.RefreshRequired && !status.RefreshFresh && status.RefreshLastSuccessUnix == 0 && status.RefreshUntilUnix == 0)
	crashRequire(t, status.StoreID == info.StoreID && status.Generation == 1 && status.CatalogueSHA256 == info.CatalogueSHA256 && status.NotAfterUnix > time.Now().Unix() && len(status.Policies) == 1 && status.Policies[0].PolicyID == info.Policies[0].PolicyID && status.Policies[0].GrantID == info.Policies[0].GrantID && status.Policies[0].ManifestSHA256 == info.ManifestSHA256)
}

func crashSnapshot(t *testing.T, root, stage string, info crashMaterial) (imagetrust.Status, imagetrust.History) {
	t.Helper()
	client := crashClient(t, root, info.Kind)
	token := crashToken(t, root, stage, info.Kind)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	for ctx.Err() == nil {
		var status imagetrust.Status
		var history imagetrust.History
		if crashGet(t, ctx, client, crashAPI(info.Kind)+"/api/v1/image-trust", token, &status) && crashGet(t, ctx, client, crashAPI(info.Kind)+"/api/v1/image-trust/history?limit=50", token, &history) {
			ack := true
			for _, entry := range history.Entries {
				ack = ack && entry.Acknowledged && len(entry.PreparedAuditHash) == 64 && len(entry.ResultAuditHash) == 64
			}
			if history.Sequence == status.Sequence && history.Total == len(history.Entries) && ack {
				crashStatusBoundary(t, status, info)
				crashRequire(t, history.Boundary == imagetrust.HistoryBoundary && history.Authorization == "BLOCKED" && !history.DeviceActionsExecuted)
				return status, history
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	crashRequire(t, false)
	return imagetrust.Status{}, imagetrust.History{}
}

// The raw log may legitimately be empty. Open/identity checks remain mandatory;
// missing or malformed files are never interpreted as a zero-event log.
func crashRaw(t *testing.T, name string, limit int64, empty bool) []byte {
	t.Helper()
	fd, err := unix.Open(name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	crashRequire(t, err == nil)
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var st, after unix.Stat_t
	crashRequire(t, unix.Fstat(fd, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFREG && st.Mode&07777 == 0600 && st.Uid == 10001 && st.Gid == 10001 && st.Nlink == 1 && st.Size <= limit && (st.Size > 0 || empty && st.Size == 0))
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	crashRequire(t, err == nil && int64(len(raw)) == st.Size && unix.Lstat(name, &after) == nil && st.Dev == after.Dev && st.Ino == after.Ino && st.Size == after.Size && st.Mtim == after.Mtim && st.Ctim == after.Ctim)
	return raw
}
func crashRawHashes(t *testing.T, root, stage, kind string) (*crashRawHash, *crashRawHash) {
	t.Helper()
	dir := filepath.Join(crashEndpoint(root, stage, kind), "data", "evidence")
	d11Dir(t, dir)
	log := crashRaw(t, filepath.Join(dir, "events.jsonl"), 4<<20, true)
	cp := crashRaw(t, filepath.Join(dir, "checkpoint.json"), 8<<10, false)
	return &crashRawHash{len(log), strings.TrimPrefix(hashed(log), "sha256:")}, &crashRawHash{len(cp), strings.TrimPrefix(hashed(cp), "sha256:")}
}

func crashCheckStatus(t *testing.T, status imagetrust.Status, stage string, sequence uint64, journal, recovery int) {
	t.Helper()
	ledger, reserved, consumed := 1, 0, 1
	if journal == 0 || stage == "prepared" && journal == 1 {
		ledger, reserved, consumed = 0, 0, 0
	}
	if stage == "reserved" && journal > 0 {
		ledger, reserved, consumed = 1, 1, 0
	}
	crashRequire(t, status.Sequence == sequence && status.LedgerEntries == ledger && status.Reserved == reserved && status.Consumed == consumed && status.RecoveryCompleted == recovery)
	state := "AVAILABLE"
	if reserved == 1 {
		state = "RESERVED"
	} else if consumed == 1 {
		state = "CONSUMED"
	}
	crashRequire(t, len(status.Policies) == 1 && status.Policies[0].State == state)
}

func crashObserve(t *testing.T, root, stage, action string, info crashMaterial) {
	t.Helper()
	previous := "prepare"
	if action == "recovered" {
		previous = "cut"
	}
	if action == "idempotent" {
		previous = "reopen-first"
	}
	prior := crashLoad(t, root, stage, info.Kind, previous)
	crashRequire(t, bytes.Equal(encode(t, prior.crashMaterial), encode(t, info)))
	status, history := crashSnapshot(t, root, stage, info)
	sequence, journal, recovery := uint64(1), 0, 0
	if action != "ready" {
		sequence, journal, recovery = 6, 1, 1
		if stage == "prepared" {
			sequence = 5
		}
		if action == "idempotent" {
			recovery = 0
		}
	}
	crashCheckStatus(t, status, stage, sequence, journal, recovery)
	crashRequire(t, history.Total == journal)
	report := crashNew(info, stage, action)
	report.Status, report.History = &status, &history
	report.AuditLog, report.Checkpoint = crashRawHashes(t, root, stage, info.Kind)
	if action == "ready" {
		crashRequire(t, report.AuditLog.Bytes == 0)
	} else {
		crashRequire(t, len(history.Entries) == 1 && history.Entries[0].ActorID == "d12-crash-admin" && history.Entries[0].Kind == "verify" && history.Entries[0].PolicyID == info.Policies[0].PolicyID)
		if action == "recovered" {
			outcome, _ := crashInitialOutcome(stage)
			crashRequire(t, len(prior.Journal) == 1 && history.Entries[0].OperationID == prior.Journal[0].Operation.ID && history.Entries[0].State == strings.ToUpper(stage) && history.Entries[0].Outcome == outcome)
		}
		if action == "idempotent" {
			crashRequire(t, prior.Inspection != nil && prior.Inspection.Sequence == status.Sequence && reflect.DeepEqual(prior.AuditLog, report.AuditLog) && reflect.DeepEqual(prior.Checkpoint, report.Checkpoint))
			recovered := crashLoad(t, root, stage, info.Kind, "recovered")
			crashRequire(t, recovered.History != nil && reflect.DeepEqual(recovered.History.Entries, history.Entries))
		}
	}
	crashSave(t, root, report)
}

func crashBody(t *testing.T, root, stage string, info crashMaterial) ([]byte, crashRequest) {
	t.Helper()
	endpoint := crashEndpoint(root, stage, info.Kind)
	policy := info.Policies[0]
	approval := d11Read(t, filepath.Join(endpoint, "original-approval.private.json"), 64<<10)
	bundle := d11Read(t, filepath.Join(endpoint, "original-bundle.private.json"), 1<<20)
	trustedRoot := d11Read(t, filepath.Join(endpoint, "trusted-root.private.json"), 1<<20)
	crashRequire(t, hashed(approval) == policy.ApprovalEnvelopeSHA256 && hashed(bundle) == policy.BundleSHA256 && hashed(trustedRoot) == policy.TrustedRootSHA256)
	body := encode(t, imagetrust.VerifyRequest{PolicyID: policy.PolicyID, Approval: approval, Bundle: bundle, TrustedRoot: trustedRoot})
	return body, crashRequest{Method: "POST", Path: d11VerifyPath, PolicyID: policy.PolicyID, GrantID: policy.GrantID,
		ApprovalSHA256: policy.ApprovalSHA256, ApprovalEnvelopeSHA256: policy.ApprovalEnvelopeSHA256,
		BundleSHA256: policy.BundleSHA256, TrustedRootSHA256: policy.TrustedRootSHA256, RequestSHA256: hashed(body), Attempts: 1}
}

func crashSend(t *testing.T, root, stage string, info crashMaterial) {
	t.Helper()
	prior := crashLoad(t, root, stage, info.Kind, "ready")
	crashRequire(t, prior.Status != nil && prior.Status.Sequence == 1)
	body, projection := crashBody(t, root, stage, info)
	d11Write(t, filepath.Join(crashEndpoint(root, stage, info.Kind), "intent-send.private"), []byte(projection.RequestSHA256+"\n"))
	client := crashClient(t, root, info.Kind)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, crashAPI(info.Kind)+d11VerifyPath, bytes.NewReader(body))
	crashRequire(t, err == nil)
	request.Header.Set("Authorization", "Bearer "+crashToken(t, root, stage, info.Kind))
	request.Header.Set("Content-Type", "application/json")
	// Exactly one Do, no HTTP/business retry and no successful-response parser.
	response, err := client.Do(request)
	if response != nil {
		response.Body.Close()
	}
	crashRequire(t, response == nil && err != nil && ctx.Err() == nil)
	var networkError net.Error
	crashRequire(t, !errors.As(err, &networkError) || !networkError.Timeout())
	crashRequire(t, errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) || errors.Is(err, net.ErrClosed))
	projection.TransportOutcome = "connection_closed"
	report := crashNew(info, stage, "send")
	report.Request = &projection
	crashSave(t, root, report)
}

func crashBlocked(t *testing.T, root, stage, action string, info crashMaterial) {
	t.Helper()
	crashRequire(t, action != "reserved" || stage == "consumed")
	crashLoad(t, root, stage, info.Kind, "ready")
	if action == "blocked" && stage == "consumed" {
		crashLoad(t, root, stage, info.Kind, "reserved")
	}
	_, projection := crashBody(t, root, stage, info)
	crashRequire(t, string(d11Read(t, filepath.Join(crashEndpoint(root, stage, info.Kind), "intent-send.private"), 128)) == projection.RequestSHA256+"\n")
	client := crashClient(t, root, info.Kind)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var status imagetrust.Status
	crashRequire(t, crashGet(t, ctx, client, crashAPI(info.Kind)+"/api/v1/image-trust", crashToken(t, root, stage, info.Kind), &status))
	crashStatusBoundary(t, status, info)
	sequence, ledger, reserved, consumed, state := uint64(2), 0, 0, 0, "AVAILABLE"
	if stage == "reserved" || action == "reserved" {
		sequence, ledger, reserved, state = 4, 1, 1, "RESERVED"
	}
	if stage == "consumed" && action == "blocked" {
		sequence, ledger, consumed, state = 5, 1, 1, "CONSUMED"
	}
	crashRequire(t, status.Sequence == sequence && status.LedgerEntries == ledger && status.Reserved == reserved && status.Consumed == consumed && status.Policies[0].State == state && status.RecoveryCompleted == 0)
	report := crashNew(info, stage, action)
	report.Status = &status
	crashSave(t, root, report)
}

func crashInitialOutcome(stage string) (string, string) {
	switch stage {
	case "prepared":
		return truststate.OutcomeInterrupted, "interrupted"
	case "reserved":
		return truststate.OutcomeVerificationReserved, "rejected"
	default:
		return truststate.OutcomeVerificationConsumed, "verification_consumed"
	}
}

func crashReopen(t *testing.T, root, stage, action string, info crashMaterial) {
	t.Helper()
	previous := "blocked"
	if action == "reopen-first" {
		previous = "recovered"
	} else if action == "reopen-final" {
		previous = "probe"
	}
	prior := crashLoad(t, root, stage, info.Kind, previous)
	crashRequire(t, bytes.Equal(encode(t, prior.crashMaterial), encode(t, info)))
	if action == "cut" {
		sent := crashLoad(t, root, stage, info.Kind, "send")
		crashRequire(t, sent.Request != nil && sent.Request.Attempts == 1 && sent.Request.HTTPStatus == 0 && sent.Request.TransportOutcome == "connection_closed")
	}
	beforeLog, beforeCheckpoint := crashRawHashes(t, root, stage, info.Kind)
	endpoint := crashEndpoint(root, stage, info.Kind)
	// Opening the actual stores never constructs product.Service and therefore
	// cannot reconcile an incomplete operation ahead of the image restart.
	store, err := truststate.Open(context.Background(), filepath.Join(endpoint, "trust"), info.Anchor)
	crashRequire(t, err == nil)
	defer store.Close()
	inspection, err := store.Inspect(context.Background())
	crashRequire(t, err == nil)
	journal, err := store.Journal(context.Background())
	crashRequire(t, err == nil)
	audit, err := evidence.Open(filepath.Join(endpoint, "data", "evidence"))
	crashRequire(t, err == nil)
	defer audit.Close()
	proof, err := audit.Verify()
	crashRequire(t, err == nil && proof.Valid && proof.Count == proof.ExpectedCount && proof.LastHash == proof.ExpectedLastHash)
	view, err := audit.RecoverySnapshot()
	crashRequire(t, err == nil)
	cut := action == "cut"
	sequence, wantJournal, wantAudit := uint64(6), 1, uint64(2)
	if stage == "prepared" {
		sequence = 5
	}
	if cut {
		sequence, wantAudit = 4, 1
		if stage == "prepared" {
			sequence, wantAudit = 2, 0
		} else if stage == "consumed" {
			sequence = 5
		}
	}
	if action == "reopen-final" {
		sequence, wantJournal, wantAudit = 10, 2, 4
	}
	crashRequire(t, inspection.Authorization == "BLOCKED" && inspection.CatalogueValid && inspection.Catalogue.StoreID == info.StoreID && inspection.Catalogue.Generation == 1 && inspection.Catalogue.SHA256 == info.CatalogueSHA256 && inspection.Sequence == sequence && len(journal) == wantJournal && proof.Count == wantAudit)
	ledger := 1
	if stage == "prepared" && action != "reopen-final" {
		ledger = 0
	}
	crashRequire(t, inspection.LedgerUsed == ledger && len(inspection.Consumptions) == ledger)
	for _, consumption := range inspection.Consumptions {
		policy := info.Policies[0]
		state := "CONSUMED"
		if stage == "reserved" {
			state = "RESERVED"
		}
		crashRequire(t, consumption.GrantID == policy.GrantID && consumption.PolicyID == policy.PolicyID && consumption.ApprovalSHA256 == policy.ApprovalSHA256 && consumption.ManifestSHA256 == info.ManifestSHA256 && consumption.Generation == 1 && consumption.CatalogueSHA256 == info.CatalogueSHA256 && consumption.Status == state)
		if state == "RESERVED" {
			crashRequire(t, consumption.EvidenceSHA256 == "")
		} else {
			crashRequire(t, regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(consumption.EvidenceSHA256))
		}
	}
	report := crashNew(info, stage, action)
	_, request := crashBody(t, root, stage, info)
	operationData := map[string]string{"policyId": request.PolicyID, "approvalSHA256": request.ApprovalEnvelopeSHA256, "bundleSHA256": request.BundleSHA256, "rootSHA256": request.TrustedRootSHA256}
	for index, entry := range journal {
		crashRequire(t, entry.Operation.ActorID == "d12-crash-admin" && entry.Operation.Kind == "verify" && entry.Operation.ScopeSHA256 == hashed(encode(t, crashScope(info.StoreID))) && d11SameData(entry.Operation.Data, operationData) && entry.Operation.AuditBaseCount == uint64(index*2))
		base, ok := view.HashAt(entry.Operation.AuditBaseCount)
		crashRequire(t, ok && base == entry.Operation.AuditBaseHash)
		prepared, hasPrepared := view.Lookup("image-trust/" + entry.Operation.ID + "/prepared")
		result, hasResult := view.Lookup("image-trust/" + entry.Operation.ID + "/result")
		binding := crashAuditBinding{OperationID: entry.Operation.ID}
		if hasPrepared {
			binding.Prepared = &prepared
			crashRequire(t, prepared.Hash == entry.Operation.PreparedAuditHash && prepared.Result == "prepared" && d11SameData(prepared.Data, entry.Operation.Data))
		}
		if hasResult {
			binding.Result = &result
			crashRequire(t, result.Hash == entry.ResultAuditHash && d11SameData(result.Data, entry.OutcomeData))
		}
		for _, event := range []*evidence.EvidenceEvent{binding.Prepared, binding.Result} {
			if event != nil {
				crashRequire(t, event.ActorID == "d12-crash-admin" && event.TraceID == entry.Operation.ID && event.Action == "image_trust.verify" && event.Target == "image-trust/"+info.StoreID)
			}
		}
		if cut {
			crashRequire(t, !hasResult && !entry.Acknowledged && entry.ResultAuditHash == "")
			state := "PREPARED"
			outcome := ""
			if stage == "prepared" {
				crashRequire(t, !hasPrepared && entry.Operation.PreparedAuditHash == "")
			} else {
				crashRequire(t, hasPrepared)
			}
			if stage == "reserved" {
				state = "RESERVED"
			} else if stage == "consumed" {
				state, outcome = "CONSUMED", truststate.OutcomeVerificationConsumed
			}
			crashRequire(t, entry.State == state && entry.Outcome == outcome)
		} else {
			outcome, resultLabel := crashInitialOutcome(stage)
			state := strings.ToUpper(stage)
			if index == 1 {
				outcome, resultLabel, state = truststate.OutcomeRejected, "rejected", "PREPARED"
				if stage == "prepared" {
					outcome, resultLabel, state = truststate.OutcomeVerificationConsumed, "verification_consumed", "CONSUMED"
				}
			}
			crashRequire(t, hasPrepared && hasResult && entry.Acknowledged && entry.State == state && entry.Outcome == outcome && result.Result == resultLabel)
		}
		if entry.State == "RESERVED" || entry.State == "CONSUMED" {
			crashRequire(t, len(inspection.Consumptions) == 1 && entry.GrantID == inspection.Consumptions[0].GrantID && entry.Generation == 1 && entry.CatalogueSHA256 == info.CatalogueSHA256 && entry.ManifestSHA256 == info.ManifestSHA256 && entry.EvidenceSHA256 == inspection.Consumptions[0].EvidenceSHA256)
		} else {
			crashRequire(t, entry.GrantID == "" && entry.Generation == 0 && entry.CatalogueSHA256 == "" && entry.ManifestSHA256 == "" && entry.EvidenceSHA256 == "")
		}
		outcomeData := map[string]string{}
		if entry.Outcome != "" && (entry.State == "RESERVED" || entry.State == "CONSUMED") {
			outcomeData = map[string]string{"grantId": entry.GrantID, "manifestSHA256": entry.ManifestSHA256, "catalogueSHA256": entry.CatalogueSHA256}
			if entry.State == "CONSUMED" {
				outcomeData["evidenceSHA256"] = entry.EvidenceSHA256
			}
		}
		crashRequire(t, d11SameData(entry.OutcomeData, outcomeData))
		report.AuditBindings = append(report.AuditBindings, binding)
	}
	if action != "cut" {
		original := crashLoad(t, root, stage, info.Kind, "cut")
		crashRequire(t, len(original.Journal) == 1 && journal[0].Operation.ID == original.Journal[0].Operation.ID && journal[0].Operation.ActorID == original.Journal[0].Operation.ActorID && d11SameData(journal[0].Operation.Data, original.Journal[0].Operation.Data))
	}
	if stage == "consumed" && !cut {
		original := crashLoad(t, root, stage, info.Kind, "cut")
		crashRequire(t, original.Inspection != nil && reflect.DeepEqual(original.Inspection.Consumptions, inspection.Consumptions))
	}
	if action != "cut" {
		var status *imagetrust.Status
		var history *imagetrust.History
		if action == "reopen-first" {
			status, history = prior.Status, prior.History
		} else {
			crashRequire(t, len(prior.Cases) == 1)
			status, history = &prior.Cases[0].StatusAfter, &prior.Cases[0].HistoryAfter
		}
		crashRequire(t, status != nil && history != nil && status.Sequence == inspection.Sequence && status.LedgerEntries == inspection.LedgerUsed && history.Total == len(journal))
		if action == "reopen-final" && stage == "prepared" {
			crashRequire(t, prior.Cases[0].Receipt != nil && len(inspection.Consumptions) == 1 && inspection.Consumptions[0].EvidenceSHA256 == prior.Cases[0].Receipt.EvidenceSHA256)
		}
		for _, entry := range journal {
			found := false
			for _, h := range history.Entries {
				if h.OperationID == entry.Operation.ID {
					crashRequire(t, h.ActorID == entry.Operation.ActorID && h.Kind == entry.Operation.Kind && h.State == entry.State && h.Outcome == entry.Outcome && h.Acknowledged == entry.Acknowledged && h.PreparedAuditHash == entry.Operation.PreparedAuditHash && h.ResultAuditHash == entry.ResultAuditHash)
					found = true
				}
			}
			crashRequire(t, found)
		}
	}
	crashRequire(t, store.Close() == nil && audit.Close() == nil)
	report.AuditLog, report.Checkpoint = crashRawHashes(t, root, stage, info.Kind)
	crashRequire(t, reflect.DeepEqual(beforeLog, report.AuditLog) && reflect.DeepEqual(beforeCheckpoint, report.Checkpoint))
	if action == "reopen-first" {
		crashRequire(t, reflect.DeepEqual(prior.AuditLog, report.AuditLog) && reflect.DeepEqual(prior.Checkpoint, report.Checkpoint))
	}
	report.Inspection, report.Journal, report.Audit = &inspection, journal, &proof
	crashSave(t, root, report)
}

func crashProbe(t *testing.T, root, stage string, info crashMaterial) {
	t.Helper()
	prior := crashLoad(t, root, stage, info.Kind, "idempotent")
	body, projection := crashBody(t, root, stage, info)
	d11Write(t, filepath.Join(crashEndpoint(root, stage, info.Kind), "intent-probe.private"), []byte(projection.RequestSHA256+"\n"))
	before, historyBefore := crashSnapshot(t, root, stage, info)
	crashRequire(t, prior.Status != nil && prior.History != nil && prior.Status.Sequence == before.Sequence && reflect.DeepEqual(prior.History.Entries, historyBefore.Entries))
	result := d11Case{Name: "probe-original", Method: "POST", Path: d11VerifyPath, PolicyID: projection.PolicyID, GrantID: projection.GrantID,
		ApprovalSHA256: projection.ApprovalSHA256, ApprovalEnvelopeSHA256: projection.ApprovalEnvelopeSHA256, BundleSHA256: projection.BundleSHA256,
		TrustedRootSHA256: projection.TrustedRootSHA256, RequestSHA256: projection.RequestSHA256, StatusBefore: before, HistoryBefore: historyBefore}
	want := 400
	if stage == "prepared" {
		want = 200
	}
	status, _, raw := d11HTTP(t, crashClient(t, root, info.Kind), "POST", crashAPI(info.Kind)+d11VerifyPath, crashToken(t, root, stage, info.Kind), "application/json", body)
	crashRequire(t, status == want)
	result.HTTPStatus = status
	if status == 200 {
		var receipt imagetrust.Receipt
		d11Decode(t, raw, &receipt)
		crashRequire(t, receipt.Boundary == imagetrust.VerifiedBoundary && receipt.Authorization == "BLOCKED" && !receipt.DeviceActionsExecuted && receipt.Verified && receipt.GrantID == projection.GrantID && receipt.Generation == 1 && receipt.CatalogueSHA256 == info.CatalogueSHA256 && receipt.ManifestSHA256 == info.ManifestSHA256 && regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(receipt.EvidenceSHA256))
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
		crashRequire(t, failure.Boundary == imagetrust.StatusBoundary && failure.Authorization == "BLOCKED" && !failure.DeviceActionsExecuted && failure.Code == "image_trust_invalid" && failure.StateMayHaveChanged)
		result.ErrorCode, result.StateMayHaveChanged = failure.Code, failure.StateMayHaveChanged
	}
	result.StatusAfter, result.HistoryAfter = crashSnapshot(t, root, stage, info)
	crashCheckStatus(t, result.StatusAfter, stage, 10, 2, 0)
	crashRequire(t, result.HistoryAfter.Total == 2)
	report := crashNew(info, stage, "probe")
	report.Cases = append(report.Cases, result)
	crashSave(t, root, report)
}
