//go:build linux

package dockerreadonlyproxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

type dockerFixture struct {
	mu       sync.Mutex
	requests []string
	inspect  int
	mutate   func(map[string]any, int)
	invalid  map[string]string
}

func (fixture *dockerFixture) roundTrip(request *http.Request) (*http.Response, error) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.requests = append(fixture.requests, request.Method+" "+request.URL.RequestURI())
	body := any(nil)
	containerID := strings.Repeat("a", 64)
	imageID := "sha256:" + strings.Repeat("b", 64)
	networkID := strings.Repeat("c", 64)
	networkName := testProject + "_m2b_probe_quarantine"
	labels := map[string]any{
		"com.docker.compose.project": testProject, "com.docker.compose.service": "probe-agent",
		"com.jydn.chengwang.component": "m2b-probe-agent-candidate", "com.jydn.chengwang.active-probes": "true",
		"com.jydn.chengwang.advisory-only": "true", "com.jydn.chengwang.egress-approved": "false",
	}
	switch {
	case strings.HasPrefix(request.URL.Path, dockerAPIPrefix+"/containers/json"):
		body = []any{map[string]any{"Id": containerID, "ImageID": imageID, "State": "running", "Labels": labels}}
	case request.URL.Path == dockerAPIPrefix+"/containers/"+containerID+"/json":
		fixture.inspect++
		body = map[string]any{
			"Id": containerID, "Image": imageID, "Name": "/fixture", "RestartCount": 0,
			"State": map[string]any{"Status": "running", "Running": true, "Paused": false, "Restarting": false,
				"OOMKilled": false, "Dead": false, "Pid": os.Getpid(), "StartedAt": "2026-10-19T00:00:00Z",
				"Health": map[string]any{"Status": "healthy", "Log": []any{map[string]any{"Output": "SECRET"}}},
			},
			"Config": map[string]any{"Image": "chengwang-m2b-probe-agent:r1", "User": "10001:10001", "Labels": labels,
				"Tty": false, "OpenStdin": false, "Env": []string{"TOKEN=SECRET"}},
			"HostConfig": map[string]any{"ReadonlyRootfs": true, "Privileged": false, "Init": true,
				"CapDrop": []string{"ALL"}, "SecurityOpt": []string{"no-new-privileges:true"}, "PidsLimit": 64,
				"Memory": 100663296, "MemoryReservation": 50331648, "NanoCpus": 250000000,
				"NetworkMode": networkName, "Tmpfs": map[string]string{"/tmp": "mode=1777,size=4m"},
				"RestartPolicy": map[string]any{"Name": "no"}},
			"Mounts": []any{map[string]any{"Type": "bind", "Source": "/SECRET", "Destination": "/x", "RW": false}},
			"NetworkSettings": map[string]any{"SandboxID": "sandbox", "SandboxKey": "/SECRET/netns",
				"Networks": map[string]any{networkName: map[string]any{"NetworkID": networkID}}},
		}
		if fixture.mutate != nil {
			fixture.mutate(body.(map[string]any), fixture.inspect)
		}
	case request.URL.Path == dockerAPIPrefix+"/images/"+imageID+"/json":
		body = map[string]any{"Id": imageID, "Config": map[string]any{"Env": []string{"SECRET"}}}
	case request.URL.Path == dockerAPIPrefix+"/networks/"+networkID:
		body = map[string]any{"Name": networkName, "Id": networkID, "Driver": "bridge", "Internal": true, "Attachable": false,
			"Containers": map[string]any{containerID: map[string]any{"Name": "fixture"}}}
	default:
		testingResponse := &http.Response{StatusCode: http.StatusNotFound, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("{}"))}
		return testingResponse, nil
	}
	raw, _ := json.Marshal(body)
	if replacement, ok := fixture.invalid[request.URL.Path]; ok {
		raw = []byte(replacement)
	}
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
}

func TestCollectorUsesOnlyFixedGETsAndReturnsSecretFreeProjection(t *testing.T) {
	fixture := &dockerFixture{}
	collector := &dockerCollector{client: &http.Client{Transport: roundTripFunc(fixture.roundTrip)}}
	snapshot, err := collector.Snapshot(context.Background(), testProject)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Container.ID != strings.Repeat("a", 64) || snapshot.Container.ProcessStartTicks == 0 || snapshot.Container.NetNSInode == 0 {
		t.Fatalf("unexpected snapshot: %+v", snapshot.Container)
	}
	raw, _ := json.Marshal(snapshot)
	if strings.Contains(string(raw), "SECRET") || strings.Contains(string(raw), "TOKEN") || strings.Contains(string(raw), "SandboxKey") {
		t.Fatal("secret-bearing Docker data escaped the projection")
	}
	if len(fixture.requests) != 5 {
		t.Fatalf("unexpected request count: %v", fixture.requests)
	}
	for _, request := range fixture.requests {
		if !strings.HasPrefix(request, "GET "+dockerAPIPrefix+"/") || strings.Contains(request, "/logs") || strings.Contains(request, "/archive") {
			t.Fatalf("unexpected Docker request: %s", request)
		}
	}
}

func TestCollectorRejectsRuntimeDriftAndAmbiguousJSON(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(map[string]any, int)
		invalid map[string]string
	}{
		{"restart-drift", func(value map[string]any, read int) {
			if read == 2 {
				value["RestartCount"] = 1
			}
		}, nil},
		{"pid-zero", func(value map[string]any, _ int) { value["State"].(map[string]any)["Pid"] = 0 }, nil},
		{"duplicate-json-key", nil, map[string]string{dockerAPIPrefix + "/images/sha256:" + strings.Repeat("b", 64) + "/json": `{"Id":"sha256:` + strings.Repeat("b", 64) + `","Id":"sha256:` + strings.Repeat("b", 64) + `"}`}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := &dockerFixture{mutate: test.mutate, invalid: test.invalid}
			collector := &dockerCollector{client: &http.Client{Transport: roundTripFunc(fixture.roundTrip)}}
			if _, err := collector.Snapshot(context.Background(), testProject); err == nil {
				t.Fatal("unsafe Docker response unexpectedly accepted")
			}
		})
	}
}
