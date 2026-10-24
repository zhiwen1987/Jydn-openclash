//go:build linux

package serverruntime

// These declarations exercise actual RunWith and loopback HTTP only when the
// isolated Linux CI executes Go tests. They have not been run locally.
import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"chengwang/internal/overview"
)

func runtimeOverviewEndpoint(t *testing.T, enabled bool) (string, *http.Client) {
	t.Helper()
	c := runtimeD9Config(t)
	c.LiveOverviewEnabled = enabled
	ctx, cancel := context.WithCancel(context.Background())
	listen, address := runtimeD9Listener(t)
	done := make(chan error, 1)
	go func() {
		done <- RunWith(Options{Config: &c, Context: ctx, Listen: listen, ShutdownTimeout: 2 * time.Second})
	}()
	transport := &http.Transport{Proxy: nil}
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	t.Cleanup(func() {
		client.CloseIdleConnections()
		cancel()
		if err := runtimeD9Result(t, done); err != nil {
			t.Fatal("actual overview runtime did not join", err)
		}
	})
	return "http://" + runtimeD9Address(t, address), client
}

func runtimeOverviewGET(t *testing.T, client *http.Client, target string) (int, []byte) {
	t.Helper()
	response, err := client.Get(target)
	if err != nil {
		t.Fatal("isolated overview request failed", err)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
	_ = response.Body.Close()
	if err != nil || len(raw) > 64<<10 || !json.Valid(raw) {
		t.Fatal("overview response exceeded its complete JSON boundary")
	}
	return response.StatusCode, raw
}

func TestServerRuntimeOverviewDefaultRemainsDisabledAndSnapshotDemo(t *testing.T) {
	base, client := runtimeOverviewEndpoint(t, false)
	status, raw := runtimeOverviewGET(t, client, base+"/api/v1/overview")
	var failure struct {
		Code string `json:"code"`
	}
	if status != http.StatusServiceUnavailable || json.Unmarshal(raw, &failure) != nil || failure.Code != "overview_not_configured" {
		t.Fatal("disabled overview route silently enabled or changed its error contract")
	}
	status, raw = runtimeOverviewGET(t, client, base+"/api/v1/snapshot")
	var legacy struct {
		DataSource string `json:"dataSource"`
	}
	if status != http.StatusOK || json.Unmarshal(raw, &legacy) != nil || legacy.DataSource != "demo" {
		t.Fatal("legacy demo snapshot changed when actual overview was disabled")
	}
}

func TestServerRuntimeOverviewEnabledUsesActualProviderWithoutInventoryFallback(t *testing.T) {
	base, client := runtimeOverviewEndpoint(t, true)
	for attempt := 0; attempt < 2; attempt++ {
		status, raw := runtimeOverviewGET(t, client, base+"/api/v1/overview")
		var actual overview.PublicSnapshot
		if status != http.StatusOK || json.Unmarshal(raw, &actual) != nil || overview.Validate(actual) != nil {
			t.Fatal("actual runtime did not inject a valid overview provider")
		}
		if actual.DataSource != "live" || actual.Mode != "candidate" || actual.GeneratedAt.IsZero() || actual.Coverage.State != "none" || len(actual.Coverage.Missing) != 7 {
			t.Fatal("unconfigured runtime fabricated current overview evidence")
		}
		if actual.Observation.Configured || actual.Observation.LastSuccessAt != nil || actual.Probe.Configured || actual.Probe.Coverage != nil {
			t.Fatal("refresh fabricated source configuration or probe coverage")
		}
		if actual.Subscription.SourceCount != nil || actual.Subscription.NodeCount != nil || actual.Subscription.InventoryState != "protected_not_read" {
			t.Fatal("actual overview exposed or fabricated protected inventory")
		}
	}
	status, raw := runtimeOverviewGET(t, client, base+"/api/v1/snapshot")
	var legacy struct {
		DataSource string `json:"dataSource"`
	}
	if status != http.StatusOK || json.Unmarshal(raw, &legacy) != nil || legacy.DataSource != "demo" {
		t.Fatal("actual overview rewrote the legacy editor snapshot")
	}
}
