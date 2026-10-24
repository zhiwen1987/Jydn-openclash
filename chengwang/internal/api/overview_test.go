package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"chengwang/internal/overview"
	"chengwang/internal/store"
)

type overviewAPIFixture struct { value overview.PublicSnapshot; err error; calls int; during func(context.Context) }
func (p *overviewAPIFixture) Snapshot(ctx context.Context) (overview.PublicSnapshot, error) {
	if p == nil { panic("typed nil overview provider must not be called") }
	p.calls++
	if p.during != nil { p.during(ctx) }
	return p.value, p.err
}
func overviewAPIValue(t *testing.T) overview.PublicSnapshot {
	t.Helper()
	p, err := overview.New(overview.Config{Mode: "lab.prod", Now: func() time.Time { return time.Date(2026, 10, 24, 12, 0, 0, 123456789, time.UTC) }})
	if err != nil { t.Fatal(err) }
	value, err := p.Snapshot(context.Background())
	if err != nil { t.Fatal(err) }
	return value
}

func TestOverviewAPIDisabledAndTypedNilReturn503WithoutDemo(t *testing.T) {
	var typedNil *overviewAPIFixture
	for _, provider := range []overview.SnapshotProvider{nil, typedNil} {
		w := httptest.NewRecorder(); New(Options{Overview: provider}).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/overview", nil))
		if w.Code != 503 || !strings.Contains(w.Body.String(), `"code":"overview_not_configured"`) || strings.Contains(w.Body.String(), "demo") || w.Header().Get("Cache-Control") != "no-store" { t.Fatal("disabled provider fell back or lost security headers") }
	}
}

func TestOverviewAPIPublicResponseIsBoundedVersionedAndAnonymous(t *testing.T) {
	p := &overviewAPIFixture{value: overviewAPIValue(t)}; h := New(Options{Overview: p})
	var first string
	for _, token := range []string{"", "Bearer PRIVATE_TOKEN"} {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/overview", nil); r.Header.Set("Authorization", token)
		w := httptest.NewRecorder(); h.ServeHTTP(w, r)
		if w.Code != 200 || w.Body.Len() > 65536 || !strings.HasSuffix(w.Body.String(), "\n") || w.Header().Get("Cache-Control") != "no-store" { t.Fatal("public overview response invalid") }
		if strings.Contains(w.Body.String(), "PRIVATE_TOKEN") || !strings.Contains(w.Body.String(), `"dataSource":"live"`) || !strings.Contains(w.Body.String(), `"sourceCount":null`) { t.Fatal("public response expanded by authorization") }
		if first != "" && first != w.Body.String() { t.Fatal("public projection depends on credential") }; first = w.Body.String()
	}
	if p.calls != 2 { t.Fatal("unexpected provider call count") }
}

func TestOverviewAPIHeadPostAndQueriesRejectBeforeCacheRead(t *testing.T) {
	p := &overviewAPIFixture{value: overviewAPIValue(t)}; h := New(Options{Overview: p})
	for _, r := range []*http.Request{httptest.NewRequest(http.MethodHead, "/api/v1/overview", nil), httptest.NewRequest(http.MethodPost, "/api/v1/overview", nil), httptest.NewRequest(http.MethodGet, "/api/v1/overview?secret=PRIVATE", nil), httptest.NewRequest(http.MethodGet, "/api/v1/overview?", nil)} {
		w := httptest.NewRecorder(); h.ServeHTTP(w, r)
		if w.Code != 400 && w.Code != 405 { t.Fatal("unsupported overview request accepted") }
		if strings.Contains(w.Body.String(), "PRIVATE") || p.calls != 0 { t.Fatal("unsupported request reflected query or reached provider") }
	}
}

func TestOverviewAPIBodyTransferAndEncodingRejectWithoutRead(t *testing.T) {
	p := &overviewAPIFixture{value: overviewAPIValue(t)}; h := New(Options{Overview: p})
	for _, alter := range []func(*http.Request){func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader("PRIVATE")); r.ContentLength = 7 }, func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader("PRIVATE")); r.ContentLength = -1 }, func(r *http.Request) { r.TransferEncoding = []string{"chunked"} }, func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }} {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/overview", nil); alter(r); w := httptest.NewRecorder(); h.ServeHTTP(w, r)
		if w.Code != 400 || p.calls != 0 || strings.Contains(w.Body.String(), "PRIVATE") { t.Fatal("body or transport encoding reached provider") }
	}
}

func TestOverviewAPIRejectsEncodedAliasInHandler(t *testing.T) {
	p := &overviewAPIFixture{value: overviewAPIValue(t)}; s := &server{options: Options{Overview: p}}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/%6fverview", nil); w := httptest.NewRecorder(); s.overview(w, r)
	if w.Code != 404 || p.calls != 0 { t.Fatal("encoded path alias reached cache") }
}

func TestOverviewAPIProviderErrorNeverReflectsPrivateCause(t *testing.T) {
	p := &overviewAPIFixture{value: overviewAPIValue(t), err: errors.New("PRIVATE_URL_TOKEN")}
	w := httptest.NewRecorder(); New(Options{Overview: p}).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/overview", nil))
	if w.Code != 503 || strings.Contains(w.Body.String(), "PRIVATE") || !strings.Contains(w.Body.String(), "overview_projection_invalid") { t.Fatal("provider error escaped fixed safe response") }
}

func TestOverviewAPIInvalidDTOAndOversizedProjectionNeverWritePartial200(t *testing.T) {
	for _, alter := range []func(*overview.PublicSnapshot){func(s *overview.PublicSnapshot) { s.GeneratedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) }, func(s *overview.PublicSnapshot) { s.Coverage.Missing = []string{strings.Repeat("PRIVATE", 12000)} }, func(s *overview.PublicSnapshot) { s.Probe.Reason = "PRIVATE" }, func(s *overview.PublicSnapshot) { s.DataSource = "demo" }} {
		value := overviewAPIValue(t); alter(&value); p := &overviewAPIFixture{value: value}
		w := httptest.NewRecorder(); New(Options{Overview: p}).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/overview", nil))
		if w.Code != 503 || w.Body.Len() > 512 || strings.Contains(w.Body.String(), "PRIVATE") || strings.Contains(w.Body.String(), `"dataSource"`) { t.Fatal("invalid DTO leaked or wrote success headers") }
	}
}

func TestOverviewAPICanceledRequestDoesNotReadProvider(t *testing.T) {
	p := &overviewAPIFixture{value: overviewAPIValue(t)}; ctx, cancel := context.WithCancel(context.Background()); cancel()
	w := httptest.NewRecorder(); New(Options{Overview: p}).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/overview", nil).WithContext(ctx))
	if w.Code != 408 || p.calls != 0 || !strings.Contains(w.Body.String(), "overview_canceled") { t.Fatal("canceled request reached provider") }
}

func TestOverviewAPIDeadlineAndLateProviderCannotReturnSuccess(t *testing.T) {
	for _, err := range []error{context.Canceled, context.DeadlineExceeded} {
		p := &overviewAPIFixture{value: overviewAPIValue(t), err: err}; w := httptest.NewRecorder()
		New(Options{Overview: p}).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/overview", nil))
		expected := 408; if errors.Is(err, context.DeadlineExceeded) { expected = 504 }
		if w.Code != expected || strings.Contains(w.Body.String(), `"dataSource"`) { t.Fatal("context failure returned stale success") }
	}
	ctx, cancel := context.WithCancel(context.Background()); defer cancel()
	p := &overviewAPIFixture{value: overviewAPIValue(t), during: func(context.Context) { cancel() }}; w := httptest.NewRecorder()
	New(Options{Overview: p}).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/overview", nil).WithContext(ctx))
	if w.Code != 408 || strings.Contains(w.Body.String(), `"dataSource"`) { t.Fatal("late successful provider bypassed caller cancellation") }
}

func TestOverviewAPIBudgetIsCooperativeAndDoesNotExtendCallerDeadline(t *testing.T) {
	value := overviewAPIValue(t)
	for _, parentBudget := range []time.Duration{time.Second, 100*time.Millisecond} {
		ctx, cancel := context.WithTimeout(context.Background(), parentBudget)
		p := &overviewAPIFixture{value: value, during: func(child context.Context) {
			deadline, ok := child.Deadline(); parentDeadline, _ := ctx.Deadline()
			if !ok || deadline.After(parentDeadline) || time.Until(deadline) > 500*time.Millisecond { t.Fatal("handler budget absent or extended parent") }
		}}; w := httptest.NewRecorder()
		New(Options{Overview: p}).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/overview", nil).WithContext(ctx)); cancel()
		if w.Code != 200 { t.Fatal("quick cache read rejected") }
	}
}

func TestOverviewAPIOriginalSnapshotRemainsExplicitDemo(t *testing.T) {
	versions, err := store.NewVersionStore(t.TempDir())
	if err != nil { t.Fatal(err) }
	h := New(Options{Versions: versions, Overview: &overviewAPIFixture{value: overviewAPIValue(t)}})
	w := httptest.NewRecorder(); h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/snapshot", nil))
	var value map[string]any
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &value) != nil || value["dataSource"] != "demo" { t.Fatal("actual overview replaced old demo snapshot") }
}
