package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHealthAcceptsFreshQuarantineRecord(t *testing.T) {
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	directory := t.TempDir()
	path := filepath.Join(directory, "health.json")
	if err := writeHealth(path, healthRecord{
		Schema:       healthSchema,
		State:        "quarantine_ready",
		UpdatedAt:    now,
		Catalog:      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ActiveProbes: false,
		AdvisoryOnly: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"health", "--health-file", path, "--max-age", "20s"}, func() time.Time { return now.Add(10 * time.Second) }); err != nil {
		t.Fatalf("health failed: %v", err)
	}
}

func TestHealthRejectsActiveProbeClaimAndStaleHeartbeat(t *testing.T) {
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	directory := t.TempDir()
	path := filepath.Join(directory, "health.json")
	base := healthRecord{
		Schema:       healthSchema,
		State:        "quarantine_ready",
		UpdatedAt:    now,
		Catalog:      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ActiveProbes: true,
		AdvisoryOnly: true,
	}
	if err := writeHealth(path, base); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"health", "--health-file", path}, func() time.Time { return now }); err == nil {
		t.Fatal("expected active probe claim to be rejected")
	}
	base.ActiveProbes = false
	if err := writeHealth(path, base); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"health", "--health-file", path, "--max-age", "10s"}, func() time.Time { return now.Add(11 * time.Second) }); err == nil {
		t.Fatal("expected stale health record to be rejected")
	}
}

func TestReadCatalogRejectsSymlink(t *testing.T) {
	directory := t.TempDir()
	realPath := filepath.Join(directory, "catalog.json")
	if err := os.WriteFile(realPath, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(directory, "catalog-link.json")
	if err := os.Symlink(realPath, linkPath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := readCatalog(linkPath); err == nil {
		t.Fatal("expected symlink catalog to be rejected")
	}
}

func TestExampleCatalogIsStrictAndQuarantined(t *testing.T) {
	catalog, err := readCatalog(filepath.Join("..", "..", "catalog.example.json"))
	if err != nil {
		t.Fatalf("example catalog is invalid: %v", err)
	}
	if catalog.Agent.ID != "candidate-guard" || len(catalog.Probes) != 1 || catalog.Probes[0].Host != "probe.invalid" {
		t.Fatalf("unexpected example catalog: %+v", catalog)
	}
}

func TestVerifyHealthLocationMustBeOutsideSpool(t *testing.T) {
	spool := t.TempDir()
	if err := verifyHealthLocation(filepath.Join(spool, "health.json"), spool); err == nil {
		t.Fatal("expected health in durable spool to be rejected")
	}
}
