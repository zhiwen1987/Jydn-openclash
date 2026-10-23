//go:build linux

package probeview

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"chengwang/internal/probe"
)

// This test uses the real immutable-segment writer and native secure reader,
// not the provider's private reader seam. It is local readback coverage, not a
// claim that a real HTTPS probe or the server/browser E2E has run.
func TestProbeViewP1NativeReverseCatalogReadbackPreservesOriginalBytes(t *testing.T) {
	catalog := viewCatalog(t, 2)
	catalog.Probes[0], catalog.Probes[1] = catalog.Probes[1], catalog.Probes[0]
	digest, err := probe.DigestCatalog(catalog)
	if err != nil || digest != catalog.Digest {
		t.Fatal("catalog digest did not preserve canonical ordering")
	}
	spool := filepath.Join(t.TempDir(), "spool")
	p, err := New(Config{Catalog: catalog, SpoolDir: spool, PollInterval: time.Second, CacheMaxAge: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if p.config.Catalog.Probes[0].ID != catalog.Probes[0].ID {
		t.Fatal("provider rewrote the input catalog to sort its display")
	}
	now := time.Now().UTC()
	p.now = func() time.Time { return now }
	store, err := probe.OpenStore(spool, catalog, probe.StoreLimits{})
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = store.Close()
		}
	}()
	for target := 0; target < 2; target++ {
		for attempt := 0; attempt < 2; attempt++ {
			result := viewResult(p, target, -time.Duration(2-attempt)*time.Second, probe.ConclusionAvailable, probe.OutcomePass)
			delta := now.Sub(viewTestTime)
			result.AttemptedAt = result.AttemptedAt.Add(delta)
			result.CompletedAt = result.CompletedAt.Add(delta)
			result.ExpiresAt = result.ExpiresAt.Add(delta)
			for _, layer := range []*probe.LayerResult{&result.Layers.DNS, &result.Layers.Connect, &result.Layers.TLS, &result.Layers.HTTP, &result.Layers.Business} {
				layer.ObservedAt, layer.ExpiresAt = layer.ObservedAt.Add(delta), layer.ExpiresAt.Add(delta)
			}
			result.ContentDigest = "sha256:" + strings.Repeat("a", 64)
			if err := store.Append(result); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	closed = true
	before := viewOriginalFiles(t, spool)
	p.refresh(context.Background())
	details := p.Details()
	if details.Status.State != "ready" || !details.Status.StorageHealthy || len(details.Samples) != 4 || details.Status.Coverage.TargetsMissing != 0 || details.Status.Coverage.RetainedSamples != 4 {
		t.Fatalf("real secure read failed: %+v", details.Status)
	}
	for _, target := range details.Targets {
		if target.State != probe.ConclusionAvailable || target.ConsecutiveSuccess != 2 {
			t.Fatalf("real verified history did not aggregate: %+v", target)
		}
	}
	if details.Targets[0].ProbeID >= details.Targets[1].ProbeID {
		t.Fatal("display target order is not canonical")
	}
	if after := viewOriginalFiles(t, spool); !reflect.DeepEqual(before, after) {
		t.Fatal("readback changed original spool bytes or file metadata")
	}
}

func viewOriginalFiles(t *testing.T, root string) map[string]string {
	t.Helper()
	files := map[string]string{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("test spool contains a nonregular file")
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		files[relative] = fmt.Sprintf("%x/%d/%d/%d", sha256.Sum256(raw), info.Size(), info.Mode(), info.ModTime().UnixNano())
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}
