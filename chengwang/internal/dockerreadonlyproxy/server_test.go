package dockerreadonlyproxy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"chengwang/internal/runtimewire"
)

const testProject = "chengwang-m2b-probe-site1-0123456789ab-candidate"

type collectorStub struct {
	project string
	value   runtimewire.Snapshot
	err     error
}

func (stub *collectorStub) Snapshot(_ context.Context, project string) (runtimewire.Snapshot, error) {
	stub.project = project
	return stub.value, stub.err
}

func TestServerExposesOnlyFixedSnapshotEndpoint(t *testing.T) {
	stub := &collectorStub{value: runtimewire.Snapshot{Schema: runtimewire.SchemaV1}}
	server, err := NewServer(stub)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, SnapshotPathPrefix+testProject+"/probe-agent", nil)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || stub.project != testProject || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unexpected response code=%d project=%q", recorder.Code, stub.project)
	}
	if strings.Contains(recorder.Body.String(), "Env") || strings.Contains(recorder.Body.String(), "Source") {
		t.Fatal("response contains a forbidden raw Docker field")
	}
}

func TestServerRejectsEveryUnapprovedRequestShape(t *testing.T) {
	server, err := NewServer(&collectorStub{})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, method, target string
		body                 string
	}{
		{"post", http.MethodPost, SnapshotPathPrefix + testProject + "/probe-agent", ""},
		{"put", http.MethodPut, SnapshotPathPrefix + testProject + "/probe-agent", ""},
		{"patch", http.MethodPatch, SnapshotPathPrefix + testProject + "/probe-agent", ""},
		{"delete", http.MethodDelete, SnapshotPathPrefix + testProject + "/probe-agent", ""},
		{"head", http.MethodHead, SnapshotPathPrefix + testProject + "/probe-agent", ""},
		{"body", http.MethodGet, SnapshotPathPrefix + testProject + "/probe-agent", "x"},
		{"query", http.MethodGet, SnapshotPathPrefix + testProject + "/probe-agent?all=1", ""},
		{"container-api", http.MethodGet, "/v1.45/containers/json", ""},
		{"logs", http.MethodGet, "/containers/" + strings.Repeat("a", 64) + "/logs", ""},
		{"encoded-slash", http.MethodGet, SnapshotPathPrefix + testProject + "%2fother/probe-agent", ""},
		{"arbitrary-project", http.MethodGet, SnapshotPathPrefix + "other" + "/probe-agent", ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.target, strings.NewReader(test.body))
			recorder := httptest.NewRecorder()
			server.ServeHTTP(recorder, request)
			if recorder.Code == http.StatusOK {
				t.Fatal("unapproved request unexpectedly succeeded")
			}
		})
	}
}

func TestServerDoesNotExposeCollectorError(t *testing.T) {
	secret := "SENSITIVE-COLLECTOR-DETAIL"
	server, err := NewServer(&collectorStub{err: errors.New(secret)})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, SnapshotPathPrefix+testProject+"/probe-agent", nil))
	if recorder.Code != http.StatusServiceUnavailable || strings.Contains(recorder.Body.String(), secret) {
		t.Fatal("collector error detail leaked")
	}
}

func TestNewServerRejectsNilCollector(t *testing.T) {
	if _, err := NewServer(nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable, got %v", err)
	}
}
