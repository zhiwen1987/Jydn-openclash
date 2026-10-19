//go:build linux && dockerdaemon

package dockerreadonlyproxy

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestDockerDaemonFixtureReadOnlySnapshotCompatibility(t *testing.T) {
	project := os.Getenv("CHENGWANG_DOCKER_FIXTURE_PROJECT")
	expectedContainerID := os.Getenv("CHENGWANG_DOCKER_FIXTURE_CONTAINER_ID")
	if !projectPattern.MatchString(project) || !fullContainerID(expectedContainerID) {
		t.Fatal("explicit Docker fixture identity is required")
	}
	collector, err := NewCollector()
	if err != nil {
		t.Fatal("fixed Docker daemon socket is unavailable")
	}
	context, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	snapshot, err := collector.Snapshot(context, project)
	if err != nil {
		t.Fatal("read-only Docker snapshot failed")
	}
	if snapshot.Schema != "chengwang.docker-runtime-snapshot/v1" || snapshot.ProjectName != project ||
		snapshot.ServiceName != "probe-agent" || snapshot.Container.ID != expectedContainerID ||
		!snapshot.Container.Running || snapshot.Container.PID <= 0 || snapshot.Container.ProcessStartTicks == 0 ||
		snapshot.Container.NetNSInode == 0 || !fullImageID(snapshot.Container.ImageID) ||
		snapshot.Image.ID != snapshot.Container.ImageID || !fullContainerID(snapshot.Network.ID) {
		t.Fatal("Docker fixture snapshot identity is incomplete")
	}
	if strings.Contains(snapshot.Container.ImageReference, "SECRET") || snapshot.Container.RestartCount != 0 {
		t.Fatal("Docker fixture projection is unsafe")
	}
}
