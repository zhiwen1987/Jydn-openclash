// Package restoreruntime compares one release-bound candidate with a
// secret-free snapshot returned by the dedicated read-only Docker collector.
// It never authorizes restoration and never returns authoritative current
// state.
package restoreruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"

	"chengwang/internal/restorecurrent"
	"chengwang/internal/runtimewire"
)

const (
	ObservationSchemaV1  = "chengwang.restore-docker-runtime-observation/v1"
	ObservationBoundary  = "ADVISORY_LOCAL_DOCKER_RUNTIME_BOUND"
	AuthorizationBlocked = "BLOCKED"
	maximumSnapshotBytes = 128 << 10
)

var (
	ErrUnsupported = errors.New("restore runtime observation is unsupported")
	ErrInvalid     = errors.New("restore runtime observation is invalid")
	ErrUnstable    = errors.New("restore runtime observation is unstable")
)

// Observation is intentionally opaque and contains no raw Docker response,
// environment value, label map, health log, or host mount source.
type Observation struct {
	schema            string
	boundary          string
	authorization     string
	candidateID       string
	projectName       string
	serviceName       string
	containerID       string
	imageID           string
	networkID         string
	pid               int
	processStartTicks uint64
	netnsDevice       uint64
	netnsInode        uint64
	runtimeSHA256     string
	blockers          []restorecurrent.BlockerCode
}

func (o Observation) Schema() string            { return o.schema }
func (o Observation) Boundary() string          { return o.boundary }
func (o Observation) Authorization() string     { return o.authorization }
func (o Observation) CandidateID() string       { return o.candidateID }
func (o Observation) ProjectName() string       { return o.projectName }
func (o Observation) ServiceName() string       { return o.serviceName }
func (o Observation) ContainerID() string       { return o.containerID }
func (o Observation) ImageID() string           { return o.imageID }
func (o Observation) NetworkID() string         { return o.networkID }
func (o Observation) PID() int                  { return o.pid }
func (o Observation) ProcessStartTicks() uint64 { return o.processStartTicks }
func (o Observation) NetNSDevice() uint64       { return o.netnsDevice }
func (o Observation) NetNSInode() uint64        { return o.netnsInode }
func (o Observation) RuntimeSHA256() string     { return o.runtimeSHA256 }
func (o Observation) Blockers() []restorecurrent.BlockerCode {
	return append([]restorecurrent.BlockerCode(nil), o.blockers...)
}

type snapshotClient interface {
	Snapshot(context.Context, string) (runtimewire.Snapshot, error)
}

// Capture observes through only the fixed read-only proxy socket. The caller
// cannot supply a socket, URL, container ID, Docker command, or transport.
func Capture(ctx context.Context, release *restorecurrent.Handle) (Observation, error) {
	client, err := productionClient()
	if err != nil {
		return Observation{}, err
	}
	return captureWithClient(ctx, release, client)
}

func captureWithClient(ctx context.Context, release *restorecurrent.Handle, client snapshotClient) (Observation, error) {
	if ctx == nil || release == nil || client == nil {
		return Observation{}, ErrInvalid
	}
	observe := func() (releaseFacts, error) {
		value, err := release.Observation()
		if err != nil {
			return releaseFacts{}, err
		}
		return factsFromObservation(value), nil
	}
	return captureFacts(ctx, observe, client)
}

type releaseFacts struct {
	schema, boundary, authorization, candidateID, projectName, serviceName string
	releaseID, imageReference, networkName, identitySHA256                 string
	identityGeneration                                                     uint64
	localRelease                                                           restorecurrent.LocalReleaseDigests
	blockers                                                               []restorecurrent.BlockerCode
}

func factsFromObservation(value restorecurrent.Observation) releaseFacts {
	return releaseFacts{
		schema: value.Schema(), boundary: value.Boundary(), authorization: value.Authorization(),
		candidateID: value.CandidateID(), projectName: value.ProjectName(), serviceName: value.ServiceName(),
		releaseID: value.ReleaseID(), imageReference: value.ExpectedImageReference(), networkName: value.ExpectedNetworkName(),
		identitySHA256: value.IdentitySHA256(), identityGeneration: value.IdentityGeneration(),
		localRelease: value.LocalRelease(), blockers: value.Blockers(),
	}
}

func captureFacts(ctx context.Context, observe func() (releaseFacts, error), client snapshotClient) (Observation, error) {
	if ctx == nil || observe == nil || client == nil {
		return Observation{}, ErrInvalid
	}
	before, err := observe()
	if err != nil || before.schema != restorecurrent.ReleaseObservationSchemaV1 ||
		before.boundary != "ADVISORY_LOCAL_RELEASE_BOUND" || before.authorization != AuthorizationBlocked ||
		before.candidateID == "" || before.releaseID == "" || before.imageReference == "" || !validBlockers(before.blockers) {
		return Observation{}, ErrInvalid
	}
	first, err := client.Snapshot(ctx, before.projectName)
	expectation := expectationFromFacts(before)
	if err != nil || validateSnapshot(first, expectation) != nil {
		return Observation{}, ErrInvalid
	}
	middle, err := observe()
	if err != nil || !sameRelease(before, middle) {
		return Observation{}, ErrUnstable
	}
	second, err := client.Snapshot(ctx, before.projectName)
	if err != nil || validateSnapshot(second, expectation) != nil || !sameSnapshot(first, second) {
		return Observation{}, ErrUnstable
	}
	after, err := observe()
	if err != nil || !sameRelease(before, after) {
		return Observation{}, ErrUnstable
	}
	digest, err := snapshotDigest(second)
	if err != nil {
		return Observation{}, ErrInvalid
	}
	blockers := append([]restorecurrent.BlockerCode(nil), before.blockers...)
	sort.Slice(blockers, func(i, j int) bool { return blockers[i] < blockers[j] })
	return Observation{
		schema: ObservationSchemaV1, boundary: ObservationBoundary, authorization: AuthorizationBlocked,
		candidateID: before.candidateID, projectName: before.projectName, serviceName: before.serviceName,
		containerID: second.Container.ID, imageID: second.Image.ID, networkID: second.Network.ID,
		pid: second.Container.PID, processStartTicks: second.Container.ProcessStartTicks,
		netnsDevice: second.Container.NetNSDevice, netnsInode: second.Container.NetNSInode,
		runtimeSHA256: digest, blockers: blockers,
	}, nil
}

func sameRelease(first, second releaseFacts) bool {
	return first.schema == second.schema && first.boundary == second.boundary &&
		first.authorization == second.authorization && first.candidateID == second.candidateID &&
		first.identityGeneration == second.identityGeneration && first.identitySHA256 == second.identitySHA256 &&
		first.projectName == second.projectName && first.serviceName == second.serviceName &&
		first.releaseID == second.releaseID && first.imageReference == second.imageReference &&
		first.networkName == second.networkName && first.localRelease == second.localRelease &&
		strings.Join(blockerStrings(first.blockers), "\x00") == strings.Join(blockerStrings(second.blockers), "\x00")
}

type runtimeExpectation struct {
	projectName    string
	serviceName    string
	imageReference string
	networkName    string
}

func expectationFromFacts(release releaseFacts) runtimeExpectation {
	return runtimeExpectation{
		projectName: release.projectName, serviceName: release.serviceName,
		imageReference: release.imageReference, networkName: release.networkName,
	}
}

func validateSnapshot(value runtimewire.Snapshot, expected runtimeExpectation) error {
	container := value.Container
	if value.Schema != runtimewire.SchemaV1 || value.ProjectName != expected.projectName ||
		value.ServiceName != expected.serviceName || container.ImageReference != expected.imageReference ||
		value.Network.Name != expected.networkName || container.NetworkMode != expected.networkName {
		return ErrInvalid
	}
	if !fullHex(container.ID, "") || !fullHex(container.ImageID, "sha256:") ||
		container.ImageID != value.Image.ID || !fullHex(value.Network.ID, "") || value.Network.SandboxID == "" {
		return ErrInvalid
	}
	if container.Status != "running" || container.HealthStatus != "healthy" || !container.Running ||
		container.Paused || container.Restarting || container.OOMKilled || container.Dead || container.PID <= 0 ||
		container.ProcessStartTicks == 0 || container.NetNSInode == 0 || container.RestartCount != 0 || container.StartedAt == "" {
		return ErrInvalid
	}
	if container.User != "10001:10001" || !container.ReadOnlyRootFS || container.Privileged || !container.Init ||
		container.TTY || container.OpenStdin || !equalStrings(container.CapDrop, []string{"ALL"}) ||
		!equalStrings(container.SecurityOpt, []string{"no-new-privileges:true"}) || container.PidsLimit != 64 ||
		container.MemoryBytes != 100663296 || container.ReservationBytes != 50331648 ||
		container.NanoCPUs != 250000000 || container.RestartPolicy != "no" {
		return ErrInvalid
	}
	if value.Network.Driver != "bridge" || !value.Network.Internal || value.Network.Attachable {
		return ErrInvalid
	}
	expectedMounts := []runtimewire.Mount{
		{Type: "bind", Destination: "/run/chengwang-probe/catalog.json", ReadOnly: true},
		{Type: "bind", Destination: "/run/chengwang-probe/dot-ca.pem", ReadOnly: true},
		{Type: "bind", Destination: "/run/chengwang-probe/egress-policy.json", ReadOnly: true},
		{Type: "bind", Destination: "/var/lib/chengwang-probe/ledger", ReadOnly: false},
		{Type: "bind", Destination: "/var/lib/chengwang-probe/results", ReadOnly: false},
	}
	if !equalMounts(container.Mounts, expectedMounts) || !equalStrings(container.Tmpfs, []string{
		"/run/m2b-probe-health:mode=0700,uid=10001,gid=10001,nosuid,nodev,noexec,size=1m",
		"/tmp:mode=1777,nosuid,nodev,noexec,size=4m",
	}) {
		return ErrInvalid
	}
	return nil
}

func sameSnapshot(first, second runtimewire.Snapshot) bool {
	firstDigest, firstErr := snapshotDigest(first)
	secondDigest, secondErr := snapshotDigest(second)
	return firstErr == nil && secondErr == nil && firstDigest == secondDigest
}

func snapshotDigest(value runtimewire.Snapshot) (string, error) {
	canonical, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte(runtimewire.SchemaV1+"\x00"), canonical...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func decodeSnapshot(raw []byte) (runtimewire.Snapshot, error) {
	if len(raw) == 0 || len(raw) > maximumSnapshotBytes || rejectDuplicateJSON(raw) != nil {
		return runtimewire.Snapshot{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var value runtimewire.Snapshot
	if err := decoder.Decode(&value); err != nil {
		return runtimewire.Snapshot{}, ErrInvalid
	}
	if _, err := decoder.Token(); err != io.EOF {
		return runtimewire.Snapshot{}, ErrInvalid
	}
	return value, nil
}

func rejectDuplicateJSON(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := scanJSON(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrInvalid
	}
	return nil
}

func scanJSON(decoder *json.Decoder, depth int) error {
	if depth > 32 {
		return ErrInvalid
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if delimiter == '{' {
		seen := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return ErrInvalid
			}
			if _, exists := seen[key]; exists {
				return ErrInvalid
			}
			seen[key] = struct{}{}
			if err := scanJSON(decoder, depth+1); err != nil {
				return err
			}
		}
	} else if delimiter == '[' {
		for decoder.More() {
			if err := scanJSON(decoder, depth+1); err != nil {
				return err
			}
		}
	} else {
		return ErrInvalid
	}
	_, err = decoder.Token()
	return err
}

func fullHex(value, prefix string) bool {
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	raw := strings.TrimPrefix(value, prefix)
	if len(raw) != 64 {
		return false
	}
	for _, character := range raw {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func equalStrings(actual, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}
	actualCopy := append([]string(nil), actual...)
	expectedCopy := append([]string(nil), expected...)
	sort.Strings(actualCopy)
	sort.Strings(expectedCopy)
	return strings.Join(actualCopy, "\x00") == strings.Join(expectedCopy, "\x00")
}

func equalMounts(actual, expected []runtimewire.Mount) bool {
	if len(actual) != len(expected) {
		return false
	}
	actualCopy := append([]runtimewire.Mount(nil), actual...)
	expectedCopy := append([]runtimewire.Mount(nil), expected...)
	sort.Slice(actualCopy, func(i, j int) bool { return actualCopy[i].Destination < actualCopy[j].Destination })
	sort.Slice(expectedCopy, func(i, j int) bool { return expectedCopy[i].Destination < expectedCopy[j].Destination })
	for index := range actualCopy {
		if actualCopy[index] != expectedCopy[index] {
			return false
		}
	}
	return true
}

func blockerStrings(values []restorecurrent.BlockerCode) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = string(value)
	}
	sort.Strings(result)
	return result
}

func validBlockers(values []restorecurrent.BlockerCode) bool {
	expected := []restorecurrent.BlockerCode{
		restorecurrent.BlockerCandidateIDAttestationMissing,
		restorecurrent.BlockerComposeSourceAttestationMissing,
		restorecurrent.BlockerComposeRenderedAttestationMissing,
		restorecurrent.BlockerImageIdentityAttestationMissing,
		restorecurrent.BlockerLiveContainerIdentityNotObserved,
		restorecurrent.BlockerLiveQuiesceNotAuthorized,
		restorecurrent.BlockerStateWriterQuiesceUnproven,
		restorecurrent.BlockerProbeStatePathBindingUnproven,
		restorecurrent.BlockerExternalTimeAnchorMissing,
	}
	return strings.Join(blockerStrings(values), "\x00") == strings.Join(blockerStrings(expected), "\x00")
}
