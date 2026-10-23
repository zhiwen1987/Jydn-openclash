//go:build linux

package main

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCandidateP1ProbeOmittedConfigurationPreservesLegacyJSON(t *testing.T) {
	raw, err := json.Marshal(productConfiguration{Addr: "127.0.0.1:1"})
	if err != nil || strings.Contains(string(raw), "probeRead") {
		t.Fatal("optional probe fields changed legacy configuration")
	}
	c, err := productProbeReadConfig(nil)
	if err != nil || c.ProbeReadEnabled || c.ProbeCatalogFile != "" || c.ProbePollInterval != 0 {
		t.Fatal("omitted probe object was not disabled")
	}
}

func TestCandidateP1ProbeExplicitConfigurationHasClosedBounds(t *testing.T) {
	root := t.TempDir()
	valid := productProbeReadConfiguration{Enabled: true, CatalogFile: filepath.Join(root, "catalog.json"), SpoolDir: filepath.Join(root, "spool"), PollIntervalSeconds: 1, CacheMaxAgeSeconds: 30}
	c, err := productProbeReadConfig(&valid)
	if err != nil || !c.ProbeReadEnabled || c.ProbePollInterval != time.Second || c.ProbeCacheMaxAge != 30*time.Second {
		t.Fatal("explicit probe configuration not mapped")
	}
	for _, mutate := range []func(*productProbeReadConfiguration){
		func(p *productProbeReadConfiguration) { p.Enabled = false },
		func(p *productProbeReadConfiguration) { p.CatalogFile = "" },
		func(p *productProbeReadConfiguration) { p.SpoolDir = "" },
		func(p *productProbeReadConfiguration) { p.PollIntervalSeconds = 0 },
		func(p *productProbeReadConfiguration) { p.PollIntervalSeconds = 61 },
		func(p *productProbeReadConfiguration) { p.PollIntervalSeconds = math.MaxInt64 },
		func(p *productProbeReadConfiguration) { p.CacheMaxAgeSeconds = 301 },
		func(p *productProbeReadConfiguration) { p.CacheMaxAgeSeconds = -1 },
		func(p *productProbeReadConfiguration) { p.PollIntervalSeconds = 60; p.CacheMaxAgeSeconds = 59 },
	} {
		invalid := valid
		mutate(&invalid)
		if _, err := productProbeReadConfig(&invalid); err != errConfiguration {
			t.Fatal("partial or overflowing probe settings accepted")
		}
	}
}

func TestCandidateP1ProbeNestedConfigurationRejectsUnknownFields(t *testing.T) {
	for _, raw := range []string{
		`{"probeRead":{"enabled":false,"unsafeReader":true}}`,
		`{"probeRead":{"enabled":false,"ownerUID":0}}`,
		`{"probeRead":{"Enabled":false}}`,
		`{"probeRead":{"enabled":true,"enabled":false}}`,
		`{"probeRead":{"enabled":"true"}}`,
	} {
		var c productConfiguration
		if strictDecode([]byte(raw), &c) == nil {
			t.Fatal("unknown, duplicate or ill-typed nested probe field accepted")
		}
	}
}

func TestCandidateP1ProbeDisabledRuntimeIgnoresInheritedEnvironment(t *testing.T) {
	f := newProductD9Fixture(t)
	t.Setenv("CHENGWANG_PROBE_READ_ENABLED", "malformed-inherited-value")
	t.Setenv("CHENGWANG_PROBE_CATALOG_FILE", "sentinel-private-no-open")
	address, stop := productD9Start(t, f)
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: f.roots}}}
	defer client.CloseIdleConnections()
	response, err := client.Get("https://" + address + "/api/v1/probes/status")
	if err != nil {
		t.Fatal("real product probe status unavailable")
	}
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	_ = response.Body.Close()
	if readErr != nil || response.StatusCode != 200 || !strings.Contains(string(raw), `"configured":false`) || !strings.Contains(string(raw), `"state":"disabled"`) || strings.Contains(string(raw), "sentinel") {
		t.Fatal("explicit product runtime inherited probe environment")
	}
	stop()
}
