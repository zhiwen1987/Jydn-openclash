package serverruntime

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var errProbeConfiguration = errors.New("probe read configuration is invalid")

// ValidateProbeReadConfiguration is shared by explicit candidate composition;
// it performs no I/O and does not inspect process environment.
func ValidateProbeReadConfiguration(c Config) error { return validateProbeConfig(c) }

// Probe inputs are deliberately all-or-nothing. Disabled composition never
// opens a catalog, spool, or probe worker, even when other runtime stores exist.
func validateProbeConfig(c Config) error {
	if !c.ProbeReadEnabled {
		if c.ProbeCatalogFile != "" || c.ProbeSpoolDir != "" || c.ProbePollInterval != 0 || c.ProbeCacheMaxAge != 0 {
			return errProbeConfiguration
		}
		return nil
	}
	for _, path := range []string{c.ProbeCatalogFile, c.ProbeSpoolDir} {
		if path == "" || strings.TrimSpace(path) != path || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) || strings.ContainsRune(path, '\x00') {
			return errProbeConfiguration
		}
	}
	if c.ProbeCatalogFile == c.ProbeSpoolDir || c.ProbePollInterval < time.Second || c.ProbePollInterval > time.Minute || c.ProbeCacheMaxAge < c.ProbePollInterval || c.ProbeCacheMaxAge > 5*time.Minute {
		return errProbeConfiguration
	}
	return nil
}

func probeConfigFromEnvironment(c *Config) error {
	enabled, err := StrictBoolEnv("CHENGWANG_PROBE_READ_ENABLED")
	if err != nil {
		return errProbeConfiguration
	}
	c.ProbeReadEnabled = enabled
	c.ProbeCatalogFile = os.Getenv("CHENGWANG_PROBE_CATALOG_FILE")
	c.ProbeSpoolDir = os.Getenv("CHENGWANG_PROBE_SPOOL_DIR")
	for _, field := range []struct {
		key string
		out *time.Duration
	}{
		{"CHENGWANG_PROBE_POLL_INTERVAL", &c.ProbePollInterval},
		{"CHENGWANG_PROBE_CACHE_MAX_AGE", &c.ProbeCacheMaxAge},
	} {
		raw := os.Getenv(field.key)
		if raw == "" {
			continue
		}
		if strings.TrimSpace(raw) != raw {
			return errProbeConfiguration
		}
		parsed, err := time.ParseDuration(raw)
		if err != nil {
			return errProbeConfiguration
		}
		*field.out = parsed
	}
	return validateProbeConfig(*c)
}
