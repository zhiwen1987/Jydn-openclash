package mihomodeploy

import (
	"context"
	"fmt"
	"io"
	"reflect"
	"sync"
	"time"
)

const labRecoveryLocalPhase = "RECOVERY_NEW_EPOCH_MARKER"
const labRecoveryLocalScope = "ACTUAL_LOOPBACK_PROXY_MARKER_NOT_INTERNET_BUSINESS_OR_AUTHORIZATION"

// Issued inline only by successful OpenIsolatedLabService, not a constructor
// from caller fixture/JSON. Copying the service core or this seal fails identity.
type labServiceFixtureCustody struct {
	service *labServiceCore
	fixture *labLocalFixture
	binding func(*labServiceFixtureCustody, *labServiceCore) bool
}

var processLabServiceFixtureIssuer = struct {
	mu     sync.Mutex
	issued map[*labServiceFixtureCustody]*labServiceCore
}{issued: map[*labServiceFixtureCustody]*labServiceCore{}}

func labServiceFixtureKnown(seal *labServiceFixtureCustody, service *labServiceCore) bool {
	i := &processLabServiceFixtureIssuer
	i.mu.Lock()
	defer i.mu.Unlock()
	return seal != nil && service != nil && i.issued[seal] == service
}

func (c *labServiceCore) revokeFixtureCustodyLocked() {
	i := &processLabServiceFixtureIssuer
	i.mu.Lock()
	delete(i.issued, c.fixtureCustody)
	i.mu.Unlock()
	c.fixtureCustody = nil
}

func (labServiceFixtureCustody) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "private service fixture custody")
}
func (labServiceFixtureCustody) MarshalJSON() ([]byte, error) { return nil, errLabRecoveryCollector }
func (*labServiceFixtureCustody) UnmarshalJSON([]byte) error  { return errLabRecoveryCollector }

func (s *labServiceFixtureCustody) current(service *LabService, authority *labRecoveryAuthority) bool {
	if s == nil || service == nil || service.core == nil || authority == nil || authority.core == nil {
		return false
	}
	c := service.core
	c.mu.Lock()
	defer c.mu.Unlock()
	return s.currentLocked(c, authority)
}

func (s *labServiceFixtureCustody) currentLocked(c *labServiceCore, authority *labRecoveryAuthority) bool {
	return s != nil && c != nil && authority != nil && authority.core != nil && labServiceFixtureKnown(s, c) && s.binding != nil && s.binding(s, c) &&
		c.fixtureCustody == s && !c.closing && !c.closed && !c.closeUncertain && !c.fixtureSettled &&
		artifactContext(c.ctx) == nil && authority.core.base == c.authority
}

type labRecoveryLocalMarkerValue struct {
	Schema                 string        `json:"schema"`
	Scope                  string        `json:"scope"`
	ExpectedRole           string        `json:"expectedRole"`
	ExpectedMarkerSHA256   string        `json:"expectedMarkerSHA256"`
	ExpectedMarkerBytes    int           `json:"expectedMarkerBytes"`
	StartedAt              time.Time     `json:"startedAt"`
	ReturnedAt             time.Time     `json:"returnedAt"`
	HandlerCompleted       bool          `json:"handlerCompleted"`
	ClientNaturalEOF       bool          `json:"clientNaturalEOF"`
	ProxyNaturalEOF        bool          `json:"proxyNaturalEOF"`
	OriginWriteComplete    bool          `json:"originWriteComplete"`
	LocalProxyMarkerProven bool          `json:"localProxyMarkerProven"`
	Route                  labLocalRoute `json:"route"`
}

type labRecoveryMarkerReceipt struct {
	owner   *labLocalFixture
	value   labRecoveryLocalMarkerValue
	binding func(*labRecoveryMarkerReceipt, *labLocalFixture) bool
}

func (labRecoveryMarkerReceipt) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "private actual route receipt")
}
func (labRecoveryMarkerReceipt) MarshalJSON() ([]byte, error) { return nil, errLabRecoveryCollector }
func (*labRecoveryMarkerReceipt) UnmarshalJSON([]byte) error  { return errLabRecoveryCollector }

func labRecoveryCloneRoute(v labLocalRoute) labLocalRoute {
	copyBody := func(p *labLocalBody) *labLocalBody {
		if p == nil {
			return nil
		}
		body := *p
		return &body
	}
	return labLocalRoute{v.Phase, v.NonceSHA256, copyBody(v.ClientResponse), copyBody(v.ProxyResponse), copyBody(v.OriginResponse),
		append([]labLocalCounter{}, v.CountersBefore...), append([]labLocalCounter{}, v.CountersAfter...), v.Matched}
}

func labRecoveryCloneMarker(v labRecoveryLocalMarkerValue) labRecoveryLocalMarkerValue {
	v.Route = labRecoveryCloneRoute(v.Route)
	return v
}

// Structural consistency only. No DTO passing this function is a receipt.
func labRecoveryMarkerValueValid(v labRecoveryLocalMarkerValue) bool {
	r := v.Route
	if v.Schema != "chengwang.mihomo-recovery-local-marker/v1" || v.Scope != labRecoveryLocalScope ||
		(v.ExpectedRole != "A" && v.ExpectedRole != "B") || !lifecycleNonzeroHash(v.ExpectedMarkerSHA256) ||
		v.ExpectedMarkerBytes < 1 || v.ExpectedMarkerBytes > 4096 || !lifecycleTime(v.StartedAt) || !lifecycleTime(v.ReturnedAt) || v.ReturnedAt.Before(v.StartedAt) ||
		!v.HandlerCompleted || !v.ClientNaturalEOF || !v.ProxyNaturalEOF || !v.OriginWriteComplete || !v.LocalProxyMarkerProven ||
		r.Phase != labRecoveryLocalPhase || !lifecycleNonzeroHash(r.NonceSHA256) || !r.Matched || len(r.CountersBefore) != 3 || len(r.CountersAfter) != 3 {
		return false
	}
	for _, body := range []*labLocalBody{r.ClientResponse, r.ProxyResponse, r.OriginResponse} {
		if body == nil || !body.Complete || body.Bytes != v.ExpectedMarkerBytes || body.SHA256 != v.ExpectedMarkerSHA256 {
			return false
		}
	}
	for n, role := range []string{"A", "B", "origin"} {
		before, after := r.CountersBefore[n], r.CountersAfter[n]
		if before.Role != role || after.Role != role {
			return false
		}
		a := []int{before.ConnectIngress, before.TunnelRequests, before.ForwardInvocations, before.OriginRequests, before.Rejected}
		b := []int{after.ConnectIngress, after.TunnelRequests, after.ForwardInvocations, after.OriginRequests, after.Rejected}
		for i := range a {
			wanted := 0
			if role == v.ExpectedRole && i < 4 || role == "origin" && i == 3 {
				wanted = 1
			}
			if a[i] < 0 || b[i] < a[i] || b[i]-a[i] != wanted {
				return false
			}
		}
	}
	return true
}

func labRecoveryMarkerWindow(v labRecoveryLocalMarkerValue, earliest, observed, deadline time.Time) bool {
	return labRecoveryMarkerValueValid(v) && lifecycleTime(earliest) && lifecycleTime(observed) &&
		!v.StartedAt.Before(earliest) && !v.ReturnedAt.After(observed) && observed.Before(deadline)
}

func (f *labLocalFixture) recoveryRoute(ctx context.Context, role string) (labRecoveryLocalMarkerValue, error) {
	var zero labRecoveryLocalMarkerValue
	if f == nil || artifactContext(ctx) != nil || (role != "A" && role != "B") {
		return zero, errLabRecoveryCollector
	}
	// Original source-owned HTTP path, not an injected route function or DTO.
	f.mu.Lock()
	closed := f.recoveryClosed || f.recoveryCount >= labRecoveryObservationLimit
	f.mu.Unlock()
	if closed {
		return zero, errLabRecoveryCollector
	}
	route := f.route(ctx, labRecoveryLocalPhase, role)
	f.mu.Lock()
	receipt := f.recoveryReceipts[route.NonceSHA256]
	f.mu.Unlock()
	return f.consumeRecoveryReceipt(ctx, receipt, route)
}

func (f *labLocalFixture) consumeRecoveryReceipt(ctx context.Context, receipt *labRecoveryMarkerReceipt, route labLocalRoute) (labRecoveryLocalMarkerValue, error) {
	var zero labRecoveryLocalMarkerValue
	if f == nil || receipt == nil {
		return zero, errLabRecoveryCollector
	}
	f.mu.Lock()
	// Admission identity is the original pointer, not its mutable DTO nonce.
	// Spend a recognized entry even if its payload was changed before rejection.
	key := ""
	known := false
	for originalKey, issued := range f.recoveryReceipts {
		if issued == receipt {
			key, known = originalKey, true
			break
		}
	}
	if known {
		delete(f.recoveryReceipts, key)
	}
	if !known || receipt.binding == nil || !receipt.binding(receipt, f) || receipt.owner != f || f.recoveryClosed {
		f.mu.Unlock()
		return zero, errLabRecoveryCollector
	}
	v := labRecoveryCloneMarker(receipt.value)
	f.mu.Unlock()
	if !reflect.DeepEqual(v.Route, route) || artifactContext(ctx) != nil || !labRecoveryMarkerValueValid(v) {
		return v, errLabRecoveryCollector
	}
	return v, nil
}

// Short lock order: service -> runtime -> base authority -> recovery store ->
// issuer. No closeMu acquisition (the native coordinator already owns it),
// process/HTTP/artifact/marker IO or diagnostic fsync occurs under this guard.
type labRecoveryLocalGuard struct {
	*labRecoveryVerifyGuard
	service *labServiceCore
	runtime *labLifecycleRuntimeCore
}

func (g *labRecoveryLocalGuard) release() {
	if g != nil && g.service != nil && g.runtime != nil {
		g.labRecoveryVerifyGuard.release()
		g.runtime.mu.Unlock()
		g.service.mu.Unlock()
		g.service, g.runtime = nil, nil
	}
}

func (c *labRecoveryCollector) authorizeLocal(headers []string, expected *labRecoveryStartedCustody, now time.Time) (*labRecoveryLocalGuard, error) {
	if c == nil || c.service == nil || c.service.core == nil || c.session == nil || c.session.core == nil {
		return nil, errLabRecoveryCollector
	}
	s := c.service.core
	s.mu.Lock()
	if c.fixtureCustody == nil || !c.fixtureCustody.currentLocked(s, c.authority) || s.runtime == nil || s.runtime.core == nil ||
		c.artifacts != s.artifacts || c.diagnostics != s.diagnostics {
		s.mu.Unlock()
		return nil, errLabRecoveryCollector
	}
	r := s.runtime.core
	r.mu.Lock()
	if r.closed || r.poisoned || r.store != nil || r.recovery == nil || r.recovery != c.session.core.store {
		r.mu.Unlock()
		s.mu.Unlock()
		return nil, errLabRecoveryCollector
	}
	guard, err := c.authority.authorizeVerify(headers, c.session, expected, now)
	if err != nil {
		r.mu.Unlock()
		s.mu.Unlock()
		return nil, err
	}
	return &labRecoveryLocalGuard{guard, s, r}, nil
}

// Exact private original of the one actual route, including a failed route's
// honest metadata. It shares the existing stage's total-byte accounting.
func (d *labServiceDiagnostics) localMarker(raw []byte) (string, error) {
	if d == nil || d.core == nil || len(raw) == 0 || len(raw) > labDiagnosticsVerification {
		return "", errLabDiagnostics
	}
	c := d.core
	c.mu.Lock()
	defer c.mu.Unlock()
	used, exists := c.captureBytes[labRecoveryCaptureStage]
	if c.closed || !exists || len(raw) > labDiagnosticsCapture-used || len(raw) > labDiagnosticsTotal-c.used {
		return "", errLabDiagnosticsLimit
	}
	if c.platform.write(labRecoveryCaptureStage+"/local-marker.json", raw, false) != nil {
		return "", errLabDiagnostics
	}
	c.used += len(raw)
	c.captureBytes[labRecoveryCaptureStage] += len(raw)
	return labConfigHash(raw), nil
}
