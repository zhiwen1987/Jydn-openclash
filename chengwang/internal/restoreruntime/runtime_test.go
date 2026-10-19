package restoreruntime

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"chengwang/internal/restorecurrent"
	"chengwang/internal/runtimewire"
)

const runtimeProject = "chengwang-m2b-probe-site1-0123456789ab-candidate"

var runtimeExpected = runtimeExpectation{
	projectName: runtimeProject, serviceName: "probe-agent",
	imageReference: "chengwang-m2b-probe-agent:r1", networkName: runtimeProject + "_m2b_probe_quarantine",
}

func validSnapshot() runtimewire.Snapshot {
	containerID := strings.Repeat("a", 64)
	imageID := "sha256:" + strings.Repeat("b", 64)
	networkID := strings.Repeat("c", 64)
	return runtimewire.Snapshot{
		Schema: runtimewire.SchemaV1, ProjectName: runtimeExpected.projectName, ServiceName: runtimeExpected.serviceName,
		Container: runtimewire.Container{
			ID: containerID, ImageID: imageID, ImageReference: runtimeExpected.imageReference, Name: "fixture",
			Status: "running", HealthStatus: "healthy", StartedAt: "2026-10-19T00:00:00Z", Running: true,
			PID: 123, ProcessStartTicks: 456, NetNSDevice: 4, NetNSInode: 5, RestartCount: 0,
			User: "10001:10001", ReadOnlyRootFS: true, Init: true, CapDrop: []string{"ALL"},
			SecurityOpt: []string{"no-new-privileges:true"}, PidsLimit: 64, MemoryBytes: 100663296,
			ReservationBytes: 50331648, NanoCPUs: 250000000, RestartPolicy: "no", NetworkMode: runtimeExpected.networkName,
			Mounts: []runtimewire.Mount{
				{Type: "bind", Destination: "/run/chengwang-probe/catalog.json", ReadOnly: true},
				{Type: "bind", Destination: "/run/chengwang-probe/dot-ca.pem", ReadOnly: true},
				{Type: "bind", Destination: "/run/chengwang-probe/egress-policy.json", ReadOnly: true},
				{Type: "bind", Destination: "/var/lib/chengwang-probe/results", ReadOnly: false},
				{Type: "bind", Destination: "/var/lib/chengwang-probe/ledger", ReadOnly: false},
			},
			Tmpfs: []string{
				"/tmp:mode=1777,nosuid,nodev,noexec,size=4m",
				"/run/m2b-probe-health:mode=0700,uid=10001,gid=10001,nosuid,nodev,noexec,size=1m",
			},
		},
		Image:   runtimewire.Image{ID: imageID},
		Network: runtimewire.Network{Name: runtimeExpected.networkName, ID: networkID, Driver: "bridge", Internal: true, SandboxID: "sandbox"},
	}
}

func TestRuntimeSnapshotAcceptsOnlyExactHardenedProductShape(t *testing.T) {
	if err := validateSnapshot(validSnapshot(), runtimeExpected); err != nil {
		t.Fatalf("valid snapshot rejected: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*runtimewire.Snapshot)
	}{
		{"project", func(v *runtimewire.Snapshot) { v.ProjectName += "-other" }},
		{"service", func(v *runtimewire.Snapshot) { v.ServiceName = "other" }},
		{"image-reference", func(v *runtimewire.Snapshot) { v.Container.ImageReference = "other" }},
		{"image-id", func(v *runtimewire.Snapshot) { v.Image.ID = "sha256:" + strings.Repeat("d", 64) }},
		{"network-id", func(v *runtimewire.Snapshot) { v.Network.ID = "short" }},
		{"network-name", func(v *runtimewire.Snapshot) { v.Network.Name = "other" }},
		{"network-mode", func(v *runtimewire.Snapshot) { v.Container.NetworkMode = "other" }},
		{"not-running", func(v *runtimewire.Snapshot) { v.Container.Running = false }},
		{"paused", func(v *runtimewire.Snapshot) { v.Container.Paused = true }},
		{"restarting", func(v *runtimewire.Snapshot) { v.Container.Restarting = true }},
		{"oom", func(v *runtimewire.Snapshot) { v.Container.OOMKilled = true }},
		{"dead", func(v *runtimewire.Snapshot) { v.Container.Dead = true }},
		{"unhealthy", func(v *runtimewire.Snapshot) { v.Container.HealthStatus = "unhealthy" }},
		{"restart-count", func(v *runtimewire.Snapshot) { v.Container.RestartCount = 1 }},
		{"pid", func(v *runtimewire.Snapshot) { v.Container.PID = 0 }},
		{"start-ticks", func(v *runtimewire.Snapshot) { v.Container.ProcessStartTicks = 0 }},
		{"netns", func(v *runtimewire.Snapshot) { v.Container.NetNSInode = 0 }},
		{"user", func(v *runtimewire.Snapshot) { v.Container.User = "0:0" }},
		{"rootfs", func(v *runtimewire.Snapshot) { v.Container.ReadOnlyRootFS = false }},
		{"privileged", func(v *runtimewire.Snapshot) { v.Container.Privileged = true }},
		{"init", func(v *runtimewire.Snapshot) { v.Container.Init = false }},
		{"tty", func(v *runtimewire.Snapshot) { v.Container.TTY = true }},
		{"stdin", func(v *runtimewire.Snapshot) { v.Container.OpenStdin = true }},
		{"caps", func(v *runtimewire.Snapshot) { v.Container.CapDrop = []string{"NET_ADMIN"} }},
		{"security-opt", func(v *runtimewire.Snapshot) { v.Container.SecurityOpt = nil }},
		{"pids", func(v *runtimewire.Snapshot) { v.Container.PidsLimit = 0 }},
		{"memory", func(v *runtimewire.Snapshot) { v.Container.MemoryBytes++ }},
		{"reservation", func(v *runtimewire.Snapshot) { v.Container.ReservationBytes++ }},
		{"cpu", func(v *runtimewire.Snapshot) { v.Container.NanoCPUs++ }},
		{"restart-policy", func(v *runtimewire.Snapshot) { v.Container.RestartPolicy = "always" }},
		{"mount", func(v *runtimewire.Snapshot) { v.Container.Mounts[0].ReadOnly = false }},
		{"tmpfs", func(v *runtimewire.Snapshot) { v.Container.Tmpfs = nil }},
		{"network-driver", func(v *runtimewire.Snapshot) { v.Network.Driver = "host" }},
		{"network-not-internal", func(v *runtimewire.Snapshot) { v.Network.Internal = false }},
		{"network-attachable", func(v *runtimewire.Snapshot) { v.Network.Attachable = true }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := validSnapshot()
			test.mutate(&value)
			if err := validateSnapshot(value, runtimeExpected); err == nil {
				t.Fatal("unsafe runtime snapshot unexpectedly accepted")
			}
		})
	}
}

func TestRuntimeSnapshotStrictDecoderRejectsAmbiguityAndSecretsRemainAbsent(t *testing.T) {
	valid, err := json.Marshal(validSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	if value, err := decodeSnapshot(valid); err != nil || validateSnapshot(value, runtimeExpected) != nil {
		t.Fatalf("valid wire snapshot rejected: %v", err)
	}
	tests := map[string][]byte{
		"empty":     nil,
		"trailing":  append(append([]byte(nil), valid...), []byte(` {}`)...),
		"unknown":   []byte(strings.Replace(string(valid), `"schema":`, `"unknown":1,"schema":`, 1)),
		"duplicate": []byte(strings.Replace(string(valid), `"schema":`, `"schema":"x","schema":`, 1)),
		"oversized": []byte(strings.Repeat(" ", maximumSnapshotBytes+1)),
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeSnapshot(raw); err == nil {
				t.Fatal("ambiguous wire snapshot unexpectedly accepted")
			}
		})
	}
	if strings.Contains(string(valid), "Env") || strings.Contains(string(valid), "Source") || strings.Contains(string(valid), "Log") {
		t.Fatal("wire schema contains a forbidden Docker field")
	}
}

func TestRuntimeSnapshotDoubleReadDetectsEveryIdentityDrift(t *testing.T) {
	base := validSnapshot()
	mutations := []func(*runtimewire.Snapshot){
		func(v *runtimewire.Snapshot) { v.Container.ID = strings.Repeat("d", 64) },
		func(v *runtimewire.Snapshot) {
			v.Container.ImageID = "sha256:" + strings.Repeat("d", 64)
			v.Image.ID = v.Container.ImageID
		},
		func(v *runtimewire.Snapshot) { v.Network.ID = strings.Repeat("d", 64) },
		func(v *runtimewire.Snapshot) { v.Container.PID++ },
		func(v *runtimewire.Snapshot) { v.Container.ProcessStartTicks++ },
		func(v *runtimewire.Snapshot) { v.Container.NetNSInode++ },
		func(v *runtimewire.Snapshot) { v.Container.RestartCount++ },
		func(v *runtimewire.Snapshot) { v.Container.StartedAt = "2026-10-19T00:00:01Z" },
	}
	for index, mutate := range mutations {
		value := validSnapshot()
		mutate(&value)
		if sameSnapshot(base, value) {
			t.Fatalf("drift mutation %d unexpectedly stable", index)
		}
	}
}

type sequenceClient struct {
	values []runtimewire.Snapshot
	calls  int
}

func (client *sequenceClient) Snapshot(_ context.Context, project string) (runtimewire.Snapshot, error) {
	if project != runtimeProject || client.calls >= len(client.values) {
		return runtimewire.Snapshot{}, ErrInvalid
	}
	value := client.values[client.calls]
	client.calls++
	return value, nil
}

func validReleaseFacts() releaseFacts {
	return releaseFacts{
		schema: restorecurrent.ReleaseObservationSchemaV1, boundary: "ADVISORY_LOCAL_RELEASE_BOUND",
		authorization: AuthorizationBlocked, candidateID: "sha256:" + strings.Repeat("d", 64),
		projectName: runtimeProject, serviceName: "probe-agent", releaseID: "r1",
		imageReference: runtimeExpected.imageReference, networkName: runtimeExpected.networkName,
		identitySHA256: "sha256:" + strings.Repeat("e", 64), identityGeneration: 1,
		localRelease: restorecurrent.LocalReleaseDigests{
			ComposeSourceSHA256: "sha256:" + strings.Repeat("1", 64), ComposeRenderedSHA256: "sha256:" + strings.Repeat("2", 64),
			RenderedSemanticSHA256: "sha256:" + strings.Repeat("3", 64), LocalBindingSHA256: "sha256:" + strings.Repeat("4", 64),
		},
		blockers: []restorecurrent.BlockerCode{
			restorecurrent.BlockerCandidateIDAttestationMissing,
			restorecurrent.BlockerComposeSourceAttestationMissing,
			restorecurrent.BlockerComposeRenderedAttestationMissing,
			restorecurrent.BlockerImageIdentityAttestationMissing,
			restorecurrent.BlockerLiveContainerIdentityNotObserved,
			restorecurrent.BlockerLiveQuiesceNotAuthorized,
			restorecurrent.BlockerStateWriterQuiesceUnproven,
			restorecurrent.BlockerProbeStatePathBindingUnproven,
			restorecurrent.BlockerExternalTimeAnchorMissing,
		},
	}
}

func TestCaptureFactsDoubleReadsAndKeepsEveryAuthorizationBlocker(t *testing.T) {
	facts := validReleaseFacts()
	observations := 0
	observe := func() (releaseFacts, error) {
		observations++
		return facts, nil
	}
	client := &sequenceClient{values: []runtimewire.Snapshot{validSnapshot(), validSnapshot()}}
	result, err := captureFacts(context.Background(), observe, client)
	if err != nil {
		t.Fatal(err)
	}
	if observations != 3 || client.calls != 2 || result.Schema() != ObservationSchemaV1 ||
		result.Boundary() != ObservationBoundary || result.Authorization() != AuthorizationBlocked ||
		result.ContainerID() != validSnapshot().Container.ID || result.RuntimeSHA256() == "" || len(result.Blockers()) != 9 {
		t.Fatalf("unexpected observation calls=%d client=%d result=%+v", observations, client.calls, result)
	}
	blockers := result.Blockers()
	blockers[0] = "MUTATED"
	if result.Blockers()[0] == "MUTATED" {
		t.Fatal("blocker result is mutable through an alias")
	}
}

func TestCaptureFactsFailsClosedOnReleaseOrRuntimeDrift(t *testing.T) {
	t.Run("release", func(t *testing.T) {
		facts := validReleaseFacts()
		calls := 0
		observe := func() (releaseFacts, error) {
			calls++
			value := facts
			if calls > 1 {
				value.identityGeneration++
			}
			return value, nil
		}
		client := &sequenceClient{values: []runtimewire.Snapshot{validSnapshot(), validSnapshot()}}
		if _, err := captureFacts(context.Background(), observe, client); !errors.Is(err, ErrUnstable) {
			t.Fatalf("expected unstable release, got %v", err)
		}
	})
	t.Run("runtime", func(t *testing.T) {
		facts := validReleaseFacts()
		observe := func() (releaseFacts, error) { return facts, nil }
		drift := validSnapshot()
		drift.Container.StartedAt = "2026-10-19T00:00:01Z"
		client := &sequenceClient{values: []runtimewire.Snapshot{validSnapshot(), drift}}
		if _, err := captureFacts(context.Background(), observe, client); !errors.Is(err, ErrUnstable) {
			t.Fatalf("expected unstable runtime, got %v", err)
		}
	})
	t.Run("missing-blocker", func(t *testing.T) {
		facts := validReleaseFacts()
		facts.blockers = facts.blockers[:8]
		observe := func() (releaseFacts, error) { return facts, nil }
		if _, err := captureFacts(context.Background(), observe, &sequenceClient{}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("expected invalid blocker set, got %v", err)
		}
	})
	t.Run("wrong-blocker", func(t *testing.T) {
		facts := validReleaseFacts()
		facts.blockers[0] = "UNREVIEWED_BLOCKER"
		observe := func() (releaseFacts, error) { return facts, nil }
		if _, err := captureFacts(context.Background(), observe, &sequenceClient{}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("expected invalid blocker set, got %v", err)
		}
	})
}
