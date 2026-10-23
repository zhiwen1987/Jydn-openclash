//go:build linux

package main

import (
	"time"

	"chengwang/internal/serverruntime"
)

// Explicit product files, not inherited environment, authorize probe inputs.
// A nil object preserves every existing candidate configuration byte-for-byte.
type productProbeReadConfiguration struct {
	Enabled             bool   `json:"enabled"`
	CatalogFile         string `json:"catalogFile"`
	SpoolDir            string `json:"spoolDir"`
	PollIntervalSeconds int64  `json:"pollIntervalSeconds"`
	CacheMaxAgeSeconds  int64  `json:"cacheMaxAgeSeconds"`
}

func productProbeReadConfig(p *productProbeReadConfiguration) (serverruntime.Config, error) {
	var c serverruntime.Config
	if p == nil {
		return c, nil
	}
	// Check before duration multiplication: untrusted JSON integers must not
	// wrap into a small, apparently valid interval.
	if p.PollIntervalSeconds < 0 || p.PollIntervalSeconds > 60 || p.CacheMaxAgeSeconds < 0 || p.CacheMaxAgeSeconds > 300 {
		return c, errConfiguration
	}
	c.ProbeReadEnabled = p.Enabled
	c.ProbeCatalogFile, c.ProbeSpoolDir = p.CatalogFile, p.SpoolDir
	c.ProbePollInterval = time.Duration(p.PollIntervalSeconds) * time.Second
	c.ProbeCacheMaxAge = time.Duration(p.CacheMaxAgeSeconds) * time.Second
	if serverruntime.ValidateProbeReadConfiguration(c) != nil {
		return serverruntime.Config{}, errConfiguration
	}
	return c, nil
}
