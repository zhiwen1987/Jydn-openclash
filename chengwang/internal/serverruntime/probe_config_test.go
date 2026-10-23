package serverruntime

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func probeConfigFixture(t *testing.T) Config {
	t.Helper()
	root := t.TempDir()
	return Config{ProbeReadEnabled: true, ProbeCatalogFile: filepath.Join(root, "catalog.json"), ProbeSpoolDir: filepath.Join(root, "spool"), ProbePollInterval: time.Second, ProbeCacheMaxAge: 30 * time.Second}
}

func probeClearEnvironment(t *testing.T) {
	t.Helper()
	for _, key := range []string{"CHENGWANG_PROBE_READ_ENABLED", "CHENGWANG_PROBE_CATALOG_FILE", "CHENGWANG_PROBE_SPOOL_DIR", "CHENGWANG_PROBE_POLL_INTERVAL", "CHENGWANG_PROBE_CACHE_MAX_AGE"} {
		t.Setenv(key, "")
	}
}

func TestServerRuntimeP1ProbeDisabledRejectsResidualConfiguration(t *testing.T) {
	if validateProbeConfig(Config{}) != nil {
		t.Fatal("disabled defaults rejected")
	}
	for _, c := range []Config{{ProbeCatalogFile: "sentinel-private-path"}, {ProbeSpoolDir: "sentinel-private-path"}, {ProbePollInterval: time.Second}, {ProbeCacheMaxAge: time.Second}} {
		if !errors.Is(validateProbeConfig(c), errProbeConfiguration) {
			t.Fatal("disabled residual input accepted")
		}
	}
}

func TestServerRuntimeP1ProbeEnabledRequiresCompleteConfiguration(t *testing.T) {
	c := probeConfigFixture(t)
	if validateProbeConfig(c) != nil {
		t.Fatal("complete configuration rejected")
	}
	for _, change := range []func(*Config){func(c *Config) { c.ProbeCatalogFile = "" }, func(c *Config) { c.ProbeSpoolDir = "" }, func(c *Config) { c.ProbePollInterval = 0 }, func(c *Config) { c.ProbeCacheMaxAge = 0 }} {
		invalid := c
		change(&invalid)
		if validateProbeConfig(invalid) == nil {
			t.Fatal("partial probe configuration accepted")
		}
	}
}

func TestServerRuntimeP1ProbeIntervalsHaveClosedBounds(t *testing.T) {
	c := probeConfigFixture(t)
	for _, pair := range [][2]time.Duration{{time.Second, time.Second}, {time.Minute, 5 * time.Minute}} {
		c.ProbePollInterval, c.ProbeCacheMaxAge = pair[0], pair[1]
		if validateProbeConfig(c) != nil {
			t.Fatal("inclusive timing boundary rejected")
		}
	}
	for _, pair := range [][2]time.Duration{{time.Second - 1, time.Second}, {time.Minute + 1, 5 * time.Minute}, {time.Second, time.Second - 1}, {time.Second, 5*time.Minute + 1}, {-time.Second, time.Second}} {
		c.ProbePollInterval, c.ProbeCacheMaxAge = pair[0], pair[1]
		if validateProbeConfig(c) == nil {
			t.Fatal("timing bound escaped")
		}
	}
}

func TestServerRuntimeP1ProbePathsAreAbsoluteCanonicalAndDistinct(t *testing.T) {
	c := probeConfigFixture(t)
	for _, path := range []string{"", "relative/catalog.json", " " + c.ProbeCatalogFile, c.ProbeCatalogFile + " ", string(filepath.Separator), c.ProbeCatalogFile + string(filepath.Separator) + "..", c.ProbeCatalogFile + "\x00"} {
		invalid := c
		invalid.ProbeCatalogFile = path
		if validateProbeConfig(invalid) == nil {
			t.Fatal("unsafe catalog path accepted")
		}
	}
	c.ProbeSpoolDir = c.ProbeCatalogFile
	if validateProbeConfig(c) == nil {
		t.Fatal("same catalog and spool accepted")
	}
}

func TestServerRuntimeP1ProbeEnvironmentIsStrictAndComplete(t *testing.T) {
	probeClearEnvironment(t)
	if c, err := ConfigFromEnvironment(); err != nil || c.ProbeReadEnabled {
		t.Fatal("probe must default disabled")
	}
	c := probeConfigFixture(t)
	t.Setenv("CHENGWANG_PROBE_READ_ENABLED", "true")
	t.Setenv("CHENGWANG_PROBE_CATALOG_FILE", c.ProbeCatalogFile)
	t.Setenv("CHENGWANG_PROBE_SPOOL_DIR", c.ProbeSpoolDir)
	t.Setenv("CHENGWANG_PROBE_POLL_INTERVAL", "1s")
	t.Setenv("CHENGWANG_PROBE_CACHE_MAX_AGE", "30s")
	got, err := ConfigFromEnvironment()
	if err != nil || !got.ProbeReadEnabled || got.ProbePollInterval != time.Second || got.ProbeCacheMaxAge != 30*time.Second {
		t.Fatal("complete probe environment not mapped")
	}
	t.Setenv("CHENGWANG_PROBE_CACHE_MAX_AGE", "")
	if _, err := ConfigFromEnvironment(); !errors.Is(err, errProbeConfiguration) {
		t.Fatal("missing required duration accepted")
	}
	for _, raw := range []string{"TRUE", " true", "1", "yes"} {
		t.Setenv("CHENGWANG_PROBE_READ_ENABLED", raw)
		if _, err := ConfigFromEnvironment(); !errors.Is(err, errProbeConfiguration) {
			t.Fatal("noncanonical enabled flag accepted")
		}
	}
}

func TestServerRuntimeP1ProbeConfigurationErrorsNeverExposeInput(t *testing.T) {
	probeClearEnvironment(t)
	t.Setenv("CHENGWANG_PROBE_READ_ENABLED", "true")
	t.Setenv("CHENGWANG_PROBE_CATALOG_FILE", "sentinel-private-credential-path")
	t.Setenv("CHENGWANG_PROBE_POLL_INTERVAL", "sentinel-private-duration")
	_, err := ConfigFromEnvironment()
	if !errors.Is(err, errProbeConfiguration) || strings.Contains(err.Error(), "sentinel") {
		t.Fatal("probe config diagnostic leaked input")
	}
}

func TestServerRuntimeP1ProbePartialConfigurationFailsBeforeListen(t *testing.T) {
	c := runtimeD9Config(t)
	c.ProbeReadEnabled = true
	called := false
	err := RunWith(Options{Config: &c, Context: context.Background(), ShutdownTimeout: time.Second, Listen: func(string, string) (net.Listener, error) {
		called = true
		return nil, errors.New("unexpected listener")
	}})
	if !errors.Is(err, errProbeConfiguration) || called {
		t.Fatal("partial probe config reached listener")
	}
	if _, err := os.Stat(filepath.Join(c.DataDir, "evidence")); !os.IsNotExist(err) {
		t.Fatal("invalid probe configuration initialized runtime stores")
	}
}

func TestServerRuntimeP1ProbeTypedConfigIgnoresProbeEnvironment(t *testing.T) {
	probeClearEnvironment(t)
	t.Setenv("CHENGWANG_PROBE_READ_ENABLED", "malformed-inherited-secret")
	t.Setenv("CHENGWANG_PROBE_CATALOG_FILE", "must-not-be-opened")
	c := runtimeD9Config(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	listen, address := runtimeD9Listener(t)
	done := make(chan error, 1)
	go func() {
		done <- RunWith(Options{Config: &c, Context: ctx, Listen: listen, ShutdownTimeout: time.Second})
	}()
	_ = runtimeD9Address(t, address)
	cancel()
	if err := runtimeD9Result(t, done); err != nil {
		t.Fatal("typed disabled probe inherited environment", err)
	}
	if os.Getenv("CHENGWANG_PROBE_READ_ENABLED") != "malformed-inherited-secret" {
		t.Fatal("runtime mutated probe environment")
	}
}
