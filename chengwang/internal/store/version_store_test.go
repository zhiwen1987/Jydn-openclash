package store

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"chengwang/internal/domain"
)

func TestVersionListFailsClosedOnUnboundedFiles(t *testing.T) {
	dir := t.TempDir()
	store, err := NewVersionStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	oversized := filepath.Join(store.dir, "oversized.json")
	if err := os.WriteFile(oversized, []byte(strings.Repeat("x", maxVersionFileBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.List(); err == nil || !strings.Contains(err.Error(), "bounded regular file") {
		t.Fatalf("oversized version file was accepted: %v", err)
	}
	if err := os.Remove(oversized); err != nil {
		t.Fatal(err)
	}
	for i := 0; i <= maxVersionFiles; i++ {
		name := filepath.Join(store.dir, fmt.Sprintf("v-%04d.json", i))
		if err := os.WriteFile(name, []byte(`{"id":"v"}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.List(); err == nil || !strings.Contains(err.Error(), "exceeds 1000 files") {
		t.Fatalf("unbounded version count was accepted: %v", err)
	}
}

func TestPublishFailsClosedAtVersionQuota(t *testing.T) {
	root := t.TempDir()
	store, err := NewVersionStore(root)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxVersionFiles; i++ {
		name := filepath.Join(store.dir, fmt.Sprintf("v-%04d.json", i))
		if err := os.WriteFile(name, []byte(`{"id":"v"}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.Publish(domain.PolicyDraft{Name: "over-quota"}, "test", ""); err == nil || !strings.Contains(err.Error(), "file limit") {
		t.Fatalf("publish at version quota was accepted: %v", err)
	}
}

func TestPublishUsesOptimisticLock(t *testing.T) {
	store, err := NewVersionStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	draft := domain.PolicyDraft{Name: "first"}
	first, err := store.Publish(draft, "test", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Publish(draft, "test", ""); err == nil {
		t.Fatal("expected stale version conflict")
	}
	if current, _ := store.CurrentID(); current != first.ID {
		t.Fatalf("unexpected current version %q", current)
	}
}

func TestConcurrentStalePublishHasSingleWinner(t *testing.T) {
	store, _ := NewVersionStore(t.TempDir())
	var wg sync.WaitGroup
	wins := make(chan struct{}, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := store.Publish(domain.PolicyDraft{Name: "candidate"}, "test", ""); err == nil {
				wins <- struct{}{}
			}
		}()
	}
	wg.Wait()
	close(wins)
	if len(wins) != 1 {
		t.Fatalf("expected one winner, got %d", len(wins))
	}
}
