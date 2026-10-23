//go:build linux && productregistry && productlifecycle && productsource && productsourcetls

package binding_test

// This independent gate never changes the Wave-1 flow/action contract. Its
// private sourceReport adapters reuse preparation and read-only reopening; they
// are not Wave-1 action evidence and must never be exported by the TLS runner.
import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"chengwang/internal/imagetrust"
)

type tlsSourceCertificates struct {
	ConfiguredCARaw []byte `json:"configuredCARaw"`
	BadChainRaw     []byte `json:"badChainRaw"`
	GoodChainRaw    []byte `json:"goodChainRaw"`
	AlternateCARaw  []byte `json:"alternateCARaw"`
}
type tlsSourcePlans struct {
	Bad  sourcePlan `json:"bad"`
	Good sourcePlan `json:"good"`
}
type tlsSourceInitial struct {
	TrustRecordSHA256 string        `json:"trustRecordSHA256"`
	AuditLog          sourceRawHash `json:"auditLog"`
	Checkpoint        sourceRawHash `json:"checkpoint"`
}
type tlsSourceMaterial struct {
	Source       sourceMaterial        `json:"source"`
	Certificates tlsSourceCertificates `json:"certificates"`
	PhasePlans   tlsSourcePlans        `json:"phasePlans"`
	Initial      tlsSourceInitial      `json:"initial"`
}
type tlsSourceObservation struct {
	Name        string             `json:"name"`
	Status      imagetrust.Status  `json:"status"`
	History     imagetrust.History `json:"history"`
	SourcePhase string             `json:"sourcePhase"`
	SourceFence sourceFence        `json:"sourceFence"`
}
type tlsSourceReport struct {
	Schema                string                 `json:"schema"`
	SourceCommit          string                 `json:"sourceCommit"`
	LocalImageID          string                 `json:"localImageID"`
	Fault                 string                 `json:"fault"`
	Kind                  string                 `json:"kind"`
	Action                string                 `json:"action"`
	Authorization         string                 `json:"authorization"`
	Production            bool                   `json:"production"`
	DeviceActionsExecuted bool                   `json:"deviceActionsExecuted"`
	Material              tlsSourceMaterial      `json:"material"`
	Observations          []tlsSourceObservation `json:"observations"`
	Offline               *sourceOffline         `json:"offline"`
}

func tlsSourceReportPath(root, fault, kind, action string) string {
	return filepath.Join(root, "evidence", "product-tls-"+fault+"-"+kind+"-"+action+".json")
}
func tlsSourceDirectory(root, fault, phase, kind string) string {
	return filepath.Join(root, "source-tls-"+fault+"-"+phase, kind)
}
func tlsSourceNewReport(material tlsSourceMaterial, fault, action string) tlsSourceReport {
	return tlsSourceReport{Schema: "chengwang.product-source-tls-driver/v1", SourceCommit: material.Source.SourceCommit,
		LocalImageID: material.Source.LocalImageID, Fault: fault, Kind: material.Source.Kind, Action: action,
		Authorization: "BLOCKED", Material: material, Observations: []tlsSourceObservation{}}
}
func tlsSourceSave(t *testing.T, root string, report tlsSourceReport) {
	t.Helper()
	d11JSON(t, tlsSourceReportPath(root, report.Fault, report.Kind, report.Action), report)
}
func tlsSourceLoad(t *testing.T, root, fault, kind, action, commit, imageID string) tlsSourceReport {
	t.Helper()
	var report tlsSourceReport
	d11Decode(t, d11Read(t, tlsSourceReportPath(root, fault, kind, action), 512<<10), &report)
	sourceRequire(t, report.Schema == "chengwang.product-source-tls-driver/v1" && report.Fault == fault && report.Kind == kind && report.Action == action && report.SourceCommit == commit && report.LocalImageID == imageID && report.Authorization == "BLOCKED" && !report.Production && !report.DeviceActionsExecuted)
	d11Decode(t, report.Material.Source.AnchorRaw, &report.Material.Source.Anchor)
	return report
}

func TestProductSourceTLSD12Fixture(t *testing.T) {
	root, fault, kind := os.Getenv("CHENGWANG_D12_TLS_ROOT"), os.Getenv("CHENGWANG_D12_TLS_FAULT"), os.Getenv("CHENGWANG_D12_TLS_KIND")
	commit, imageID, action := os.Getenv("CHENGWANG_D12_TLS_COMMIT"), os.Getenv("CHENGWANG_D12_TLS_IMAGE_ID"), os.Getenv("CHENGWANG_D12_TLS_ACTION")
	sourceRequire(t, os.Getuid() == 10001 && os.Geteuid() == 10001 && os.Getgid() == 10001 && os.Getegid() == 10001)
	sourceRequire(t, regexp.MustCompile(`^/tmp/chengwang-product-lifecycle-[0-9a-f]{32}$`).MatchString(root) && (fault == "ca" || fault == "san" || fault == "spki") && (kind == "message-signature" || kind == "dsse"))
	sourceRequire(t, regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(commit) && regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(imageID))
	d11Dir(t, root)
	d11Dir(t, filepath.Join(root, "evidence"))
	sourceRequire(t, string(d11Read(t, filepath.Join(root, ".fixture-owner"), 64)) == strings.TrimPrefix(root, "/tmp/chengwang-product-lifecycle-")+"\n")
	archive := os.Getenv("CHENGWANG_D12_TLS_ARCHIVE")
	sourceRequire(t, archive == filepath.Join(root, "bin", "product-image.private.tar"))
	t.Setenv("CHENGWANG_D11_KIND", kind)
	t.Setenv("CHENGWANG_D11_ARCHIVE", archive)
	switch action {
	case "prepare":
		tlsSourcePrepare(t, root, fault, kind, commit, imageID)
	case "reject", "recover":
		tlsSourceObserve(t, root, fault, kind, commit, imageID, action)
	case "reopen":
		tlsSourceReopen(t, root, fault, kind, commit, imageID)
	default:
		sourceRequire(t, false)
	}
	fmt.Printf("D12_PRODUCT_SOURCE_TLS_%s=PASS fault=%s kind=%s authorization=BLOCKED production=false\n", strings.ToUpper(action), fault, kind)
}

func tlsSourceCertificate(t *testing.T, raw []byte) *x509.Certificate {
	t.Helper()
	block, remainder := pem.Decode(raw)
	sourceRequire(t, block != nil && block.Type == "CERTIFICATE" && len(block.Headers) == 0 && len(bytes.TrimSpace(remainder)) == 0)
	certificate, err := x509.ParseCertificate(block.Bytes)
	sourceRequire(t, err == nil)
	return certificate
}
func tlsSourceCertificateMaterial(t *testing.T, root, fault string, info sourceMaterial) tlsSourceCertificates {
	t.Helper()
	material := tlsSourceCertificates{ConfiguredCARaw: d11Read(t, filepath.Join(root, "source-ca.pem"), 256<<10),
		GoodChainRaw: d11Read(t, filepath.Join(root, "source-cert.pem"), 256<<10),
		BadChainRaw:  d11Read(t, filepath.Join(root, "tls-"+fault+"-bad-cert.pem"), 256<<10), AlternateCARaw: []byte{}}
	rootCertificate := tlsSourceCertificate(t, material.ConfiguredCARaw)
	good, bad := tlsSourceCertificate(t, material.GoodChainRaw), tlsSourceCertificate(t, material.BadChainRaw)
	sourceRequire(t, rootCertificate.IsCA && !good.IsCA && !bad.IsCA && info.FeedCASHA256 == hashed(material.ConfiguredCARaw) && info.FeedSPKI == hashed(good.RawSubjectPublicKeyInfo))
	roots := x509.NewCertPool()
	roots.AddCert(rootCertificate)
	now := time.Now()
	for _, leaf := range []*x509.Certificate{good, bad} {
		sourceRequire(t, now.After(leaf.NotBefore) && now.Before(leaf.NotAfter))
	}
	verify := func(leaf *x509.Certificate, pool *x509.CertPool, hostname string) error {
		_, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: hostname, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
		return err
	}
	sourceRequire(t, verify(good, roots, "feed.fixture.invalid") == nil)
	switch fault {
	case "ca":
		material.AlternateCARaw = d11Read(t, filepath.Join(root, "source-alt-ca.pem"), 256<<10)
		alternate := tlsSourceCertificate(t, material.AlternateCARaw)
		sourceRequire(t, alternate.IsCA && !bytes.Equal(alternate.Raw, rootCertificate.Raw) && !bytes.Equal(alternate.RawSubjectPublicKeyInfo, rootCertificate.RawSubjectPublicKeyInfo))
		otherRoots := x509.NewCertPool()
		otherRoots.AddCert(alternate)
		sourceRequire(t, bytes.Equal(good.RawSubjectPublicKeyInfo, bad.RawSubjectPublicKeyInfo) && bad.VerifyHostname("feed.fixture.invalid") == nil && verify(bad, roots, "") != nil && verify(bad, otherRoots, "feed.fixture.invalid") == nil)
	case "san":
		sourceRequire(t, bytes.Equal(good.RawSubjectPublicKeyInfo, bad.RawSubjectPublicKeyInfo) &&
			reflect.DeepEqual(good.DNSNames, []string{"feed.fixture.invalid"}) && reflect.DeepEqual(bad.DNSNames, []string{"wrong.fixture.invalid"}) &&
			reflect.DeepEqual(good.IPAddresses, bad.IPAddresses) && reflect.DeepEqual(good.EmailAddresses, bad.EmailAddresses) &&
			reflect.DeepEqual(good.URIs, bad.URIs) && verify(bad, roots, "wrong.fixture.invalid") == nil && bad.VerifyHostname("feed.fixture.invalid") != nil)
	case "spki":
		sourceRequire(t, !bytes.Equal(good.RawSubjectPublicKeyInfo, bad.RawSubjectPublicKeyInfo) && verify(bad, roots, "feed.fixture.invalid") == nil)
	}
	return material
}

func tlsSourcePrepare(t *testing.T, root, fault, kind, commit, imageID string) {
	t.Helper()
	flow := "tls-" + fault
	// This generic helper writes private legacy-format material only. No old
	// fixture entrypoint, action marker or independent Wave-1 gate is invoked.
	sourcePrepare(t, root, flow, kind, commit, imageID)
	prepared := sourceLoad(t, root, flow, kind, "prepare")
	info := prepared.Material
	material := tlsSourceMaterial{Source: info, Certificates: tlsSourceCertificateMaterial(t, root, fault, info)}
	g1 := sourceCatalogueNamed(t, info, "g1")
	raw := encode(t, map[string]any{"schema": "chengwang.product-source-plan/v1", "epoch": 1,
		"responses": map[string]any{"latest.json": map[string]any{"mode": "json", "bodySHA256": strings.TrimPrefix(g1.SHA256, "sha256:")}}})
	for _, phase := range []string{"bad", "good"} {
		directory := tlsSourceDirectory(root, fault, phase, kind)
		for _, name := range []string{filepath.Dir(directory), directory, filepath.Join(directory, "feed"), filepath.Join(directory, "feed", "bodies")} {
			sourceDir(t, name)
		}
		d11Write(t, filepath.Join(directory, "feed", "bodies", strings.TrimPrefix(g1.SHA256, "sha256:")+".json"), g1.Raw)
		d11Write(t, filepath.Join(directory, "feed", "plan.json"), raw)
	}
	material.PhasePlans = tlsSourcePlans{Bad: sourcePlan{Epoch: 1, Raw: raw, SHA256: hashed(raw)}, Good: sourcePlan{Epoch: 1, Raw: bytes.Clone(raw), SHA256: hashed(raw)}}
	endpoint := sourceEndpoint(root, flow, kind)
	material.Initial = tlsSourceInitial{TrustRecordSHA256: sourceRecordHash(t, endpoint),
		AuditLog:   sourceRawDigest(sourceRaw(t, filepath.Join(endpoint, "data", "evidence", "events.jsonl"), 4<<20, true)),
		Checkpoint: sourceRawDigest(sourceRaw(t, filepath.Join(endpoint, "data", "evidence", "checkpoint.json"), 8<<10, false))}
	sourceRequire(t, material.Initial.AuditLog.Bytes == 0)
	tlsSourceSave(t, root, tlsSourceNewReport(material, fault, "prepare"))
}

func tlsSourceEvents(t *testing.T, ctx context.Context, root, fault, phase, kind string) ([]sourceEvent, sourceFence) {
	t.Helper()
	name := filepath.Join(tlsSourceDirectory(root, fault, phase, kind), "feed", "events.jsonl")
	for ctx.Err() == nil {
		raw, ok := sourceTryRaw(name, 4<<20, true)
		if !ok || len(raw) > 0 && raw[len(raw)-1] != '\n' {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		events := []sourceEvent{}
		if len(raw) > 0 {
			for _, line := range bytes.Split(bytes.TrimSuffix(raw, []byte{'\n'}), []byte{'\n'}) {
				var event sourceEvent
				d11Decode(t, line, &event)
				sourceRequire(t, event.Schema == "chengwang.product-source-event/v1" && event.Ordinal == len(events)+1 && event.Connection > 0 && event.Connection <= 512 && len(events) < 4096)
				sourceRequire(t, event.Event == "connect" || event.Event == "tls" || event.Event == "http" || event.Event == "close")
				events = append(events, event)
			}
		}
		return events, sourceFence{EventCount: len(events), SHA256: strings.TrimPrefix(hashed(raw), "sha256:")}
	}
	sourceRequire(t, false)
	return nil, sourceFence{}
}
func tlsSourceRejectedAttempts(t *testing.T, events []sourceEvent) int {
	t.Helper()
	connections := map[int][]sourceEvent{}
	for _, event := range events {
		// A successful server-side TLS event is not an HTTP acceptance and
		// cannot identify the client's pin decision. Never invent that cause.
		sourceRequire(t, event.Event != "http")
		connections[event.Connection] = append(connections[event.Connection], event)
	}
	eligible := 0
	for _, connection := range connections {
		sourceRequire(t, connection[0].Event == "connect" && connection[0].Reason == "accepted" && len(connection) <= 3)
		if len(connection) >= 2 {
			sourceRequire(t, connection[1].Event == "tls")
		}
		if len(connection) == 3 {
			sourceRequire(t, connection[2].Event == "close")
			if connection[2].Reason == "closed" && (connection[1].Reason == "failed" || connection[1].Reason == "ok") {
				eligible++
			}
		}
	}
	return eligible
}
func tlsSourceGoodResponse(events []sourceEvent, info sourceMaterial, plan sourcePlan) bool {
	for _, event := range events {
		if event.Event == "http" && event.Epoch == 1 && event.PlanSHA256 == strings.TrimPrefix(plan.SHA256, "sha256:") && event.PathClass == "latest" && event.Generation == 0 && event.Mode == "json" && event.Reason == "planned" && event.Status == 200 && event.TLS && !event.AuthPresent && event.WireComplete && event.WrittenBytes == event.WireBytes && event.RepresentationSHA256 == strings.TrimPrefix(info.Catalogue1SHA256, "sha256:") {
			return true
		}
	}
	return false
}

func tlsSourceObserve(t *testing.T, root, fault, kind, commit, imageID, action string) {
	t.Helper()
	prepared := tlsSourceLoad(t, root, fault, kind, "prepare", commit, imageID)
	material, flow, phase, name := prepared.Material, "tls-"+fault, "bad", "rejected"
	if action == "recover" {
		rejected := tlsSourceLoad(t, root, fault, kind, "reject", commit, imageID)
		sourceRequire(t, reflect.DeepEqual(rejected.Material, material) && len(rejected.Observations) == 1 && !rejected.Observations[0].Status.RefreshFresh)
		phase, name = "good", "recovered"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	// Establish a real causal source-event prefix before observing API state.
	for ctx.Err() == nil {
		events, _ := tlsSourceEvents(t, ctx, root, fault, phase, kind)
		if action == "reject" && tlsSourceRejectedAttempts(t, events) >= 2 || action == "recover" && tlsSourceGoodResponse(events, material.Source, material.PhasePlans.Good) {
			break
		}
		time.Sleep(30 * time.Millisecond)
	}
	sourceRequire(t, ctx.Err() == nil)
	client := d11Client(t, root, false)
	token := string(d11Read(t, filepath.Join(sourceEndpoint(root, flow, kind), "admin-token.private"), 4096))
	for ctx.Err() == nil {
		status, history := sourceSnapshot(t, ctx, client, kind, token)
		sourceRequire(t, sourceState(material.Source, status, history, 1, 1, 0))
		if action == "reject" {
			sourceRequire(t, !status.RefreshFresh && status.RefreshLastSuccessUnix == 0 && status.RefreshUntilUnix == 0)
		} else if !status.RefreshFresh || status.RefreshLastSuccessUnix <= 0 || status.RefreshUntilUnix <= status.ObservedAtUnix {
			time.Sleep(30 * time.Millisecond)
			continue
		}
		events, fence := tlsSourceEvents(t, ctx, root, fault, phase, kind)
		if action == "reject" {
			sourceRequire(t, tlsSourceRejectedAttempts(t, events) >= 2)
		} else {
			sourceRequire(t, tlsSourceGoodResponse(events, material.Source, material.PhasePlans.Good))
		}
		report := tlsSourceNewReport(material, fault, action)
		report.Observations = append(report.Observations, tlsSourceObservation{Name: name, Status: status, History: history, SourcePhase: phase, SourceFence: fence})
		if action == "recover" {
			// Private adapter for the existing read-only opener only. This is
			// the actual recovered API snapshot, not a fabricated Wave-1 run.
			adapter := sourceNewReport(material.Source, flow, "run")
			adapter.Observations = []sourceObservation{{Name: name, Status: status, History: history, SourceFence: fence}}
			sourceSave(t, root, adapter)
		}
		tlsSourceSave(t, root, report)
		return
	}
	sourceRequire(t, false)
}

func tlsSourceReopen(t *testing.T, root, fault, kind, commit, imageID string) {
	t.Helper()
	prepared := tlsSourceLoad(t, root, fault, kind, "prepare", commit, imageID)
	recovered := tlsSourceLoad(t, root, fault, kind, "recover", commit, imageID)
	sourceRequire(t, reflect.DeepEqual(prepared.Material, recovered.Material) && len(recovered.Observations) == 1 && recovered.Observations[0].Status.RefreshFresh)
	flow := "tls-" + fault
	sourceReopen(t, root, flow, kind, commit, imageID)
	private := sourceLoad(t, root, flow, kind, "reopen")
	sourceRequire(t, private.Offline != nil && private.Offline.TrustRecordSHA256 == prepared.Material.Initial.TrustRecordSHA256 && private.Offline.AuditLog == prepared.Material.Initial.AuditLog && private.Offline.Checkpoint == prepared.Material.Initial.Checkpoint)
	report := tlsSourceNewReport(prepared.Material, fault, "reopen")
	report.Offline = private.Offline
	tlsSourceSave(t, root, report)
}
