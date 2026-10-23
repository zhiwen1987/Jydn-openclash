//go:build linux

package serverruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"chengwang/internal/probe"
	"chengwang/internal/probeview"
)

func runtimeProbeInputs(t *testing.T) (Config, []byte) {
	t.Helper()
	c := runtimeD9Config(t)
	root := t.TempDir()
	c.ProbeReadEnabled = true
	c.ProbeCatalogFile = filepath.Join(root, "catalog.json")
	c.ProbeSpoolDir = filepath.Join(root, "spool")
	c.ProbePollInterval = time.Second
	c.ProbeCacheMaxAge = 2 * time.Second
	for _, path := range []string{c.ProbeSpoolDir, filepath.Join(c.ProbeSpoolDir, "segments")} {
		if os.Mkdir(path, 0700) != nil {
			t.Fatal("provision private probe input")
		}
	}
	catalog := probe.Catalog{Schema: probe.CatalogSchemaV1, Revision: "runtime-p1", Agent: probe.AgentSpec{ID: "runtime-agent", Independence: probe.IndependenceP1, AdvisoryOnly: true}, Paths: []probe.Path{{ID: "direct", Kind: probe.PathKindDirect}}, Probes: []probe.Target{{ID: "business", PathID: "direct", Kind: probe.ProbeHTTPS, Host: "service.example.com", Port: 443, RequestPath: "/health", Method: "GET", ExpectedStatus: []int{200}, IntervalSeconds: 30, TimeoutSeconds: 1, TTLSeconds: 30, MaxBodyBytes: 1024}}}
	raw, err := json.Marshal(catalog)
	if err != nil || os.WriteFile(c.ProbeCatalogFile, raw, 0600) != nil {
		t.Fatal("provision private catalog")
	}
	return c, raw
}

func TestServerRuntimeP1ProbeEnabledReadbackJoinsWithoutChangingInputs(t *testing.T) {
	c, original := runtimeProbeInputs(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	listen, address := runtimeD9Listener(t)
	done := make(chan error, 1)
	go func() {
		done <- RunWith(Options{Config: &c, Context: ctx, Listen: listen, ShutdownTimeout: 2 * time.Second})
	}()
	base := "http://" + runtimeD9Address(t, address)
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil}}
	defer client.CloseIdleConnections()
	deadline := time.Now().Add(3 * time.Second)
	observed := false
	for time.Now().Before(deadline) {
		response, err := client.Get(base + "/api/v1/probes/status")
		if err != nil {
			t.Fatal("probe status route unavailable")
		}
		raw, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
		_ = response.Body.Close()
		var status probeview.Status
		if err != nil || response.StatusCode != 200 || json.Unmarshal(raw, &status) != nil || strings.Contains(string(raw), "runtime-agent") || strings.Contains(string(raw), "service.example.com") {
			t.Fatal("anonymous real runtime status unsafe")
		}
		if status.Configured && status.Running && status.StorageHealthy && status.Reason == "no_current_evidence" {
			observed = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !observed {
		t.Fatal("synchronous probe worker did not publish actual empty-store read")
	}
	cancel()
	if err := runtimeD9Result(t, done); err != nil {
		t.Fatal("probe worker did not join runtime", err)
	}
	raw, err := os.ReadFile(c.ProbeCatalogFile)
	if err != nil || !bytes.Equal(raw, original) {
		t.Fatal("probe readback changed catalog bytes")
	}
	entries, err := os.ReadDir(c.ProbeSpoolDir)
	if err != nil || len(entries) != 1 || entries[0].Name() != "segments" {
		t.Fatal("probe readback created input-side files")
	}
	segments, err := os.ReadDir(filepath.Join(c.ProbeSpoolDir, "segments"))
	if err != nil || len(segments) != 0 {
		t.Fatal("probe readback changed spool")
	}
}

func TestServerRuntimeP1ProbeUnsafeCatalogFailsBeforeListen(t *testing.T) {
	c, _ := runtimeProbeInputs(t)
	target := c.ProbeCatalogFile
	c.ProbeCatalogFile = filepath.Join(filepath.Dir(target), "catalog-link.json")
	if os.Symlink(target, c.ProbeCatalogFile) != nil {
		t.Fatal("provision catalog symlink")
	}
	called := false
	err := RunWith(Options{Config: &c, Context: context.Background(), ShutdownTimeout: time.Second, Listen: func(string, string) (net.Listener, error) {
		called = true
		return nil, errors.New("unexpected listener")
	}})
	if err == nil || called || strings.Contains(err.Error(), c.ProbeCatalogFile) {
		t.Fatal("unsafe catalog reached listener or leaked path")
	}
	if _, err := os.Stat(filepath.Join(c.DataDir, "evidence")); !os.IsNotExist(err) {
		t.Fatal("unsafe catalog initialized runtime stores")
	}
}
