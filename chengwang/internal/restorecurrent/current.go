// Package restorecurrent collects one process-local, read-only diagnostic
// observation of a probe candidate configuration namespace. The observation is deliberately
// blocked: it is not an authoritative current-state contract, cannot
// authorize a live action, and is not a production restore coordinator input.
package restorecurrent

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"chengwang/internal/probe"
	"chengwang/internal/restoreclock"
	"chengwang/internal/restorelease"
)

const (
	ObservationSchemaV1         = "chengwang.restore-current-observation/v1"
	IdentityObservationSchemaV1 = "chengwang.restore-identity-observation/v1"
	ReleaseObservationSchemaV1  = "chengwang.restore-local-release-observation/v1"
)

const (
	serviceName             = "probe-agent"
	stateMountTarget        = "/var/lib/chengwang-probe"
	observationWindow       = 30 * time.Second
	observationMaximumDrift = 2 * time.Second
)

var safeInstance = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,19}$`)

var (
	ErrUnsupported = errors.New("restore current observation is unsupported")
	ErrClosed      = errors.New("restore current observation is closed")
	ErrPoisoned    = errors.New("restore current observation is poisoned")
	ErrInvalid     = errors.New("restore current observation input is invalid")
)

type BlockerCode string

const (
	BlockerCandidateIDAttestationMissing     BlockerCode = "CANDIDATE_ID_ATTESTATION_MISSING"
	BlockerComposeSourceAttestationMissing   BlockerCode = "COMPOSE_SOURCE_ATTESTATION_MISSING"
	BlockerComposeRenderedAttestationMissing BlockerCode = "COMPOSE_RENDERED_ATTESTATION_MISSING"
	BlockerImageIdentityAttestationMissing   BlockerCode = "IMAGE_IDENTITY_ATTESTATION_MISSING"
	BlockerLiveContainerIdentityNotObserved  BlockerCode = "LIVE_CONTAINER_IDENTITY_NOT_OBSERVED"
	BlockerLiveQuiesceNotAuthorized          BlockerCode = "LIVE_QUIESCE_NOT_AUTHORIZED"
	BlockerStateWriterQuiesceUnproven        BlockerCode = "STATE_WRITER_QUIESCE_UNPROVEN"
	BlockerProbeStatePathBindingUnproven     BlockerCode = "PROBE_STATE_PATH_BINDING_UNPROVEN"
	BlockerExternalTimeAnchorMissing         BlockerCode = "EXTERNAL_TIME_ANCHOR_MISSING"
)

var mandatoryBlockers = []BlockerCode{
	BlockerCandidateIDAttestationMissing,
	BlockerComposeSourceAttestationMissing,
	BlockerComposeRenderedAttestationMissing,
	BlockerImageIdentityAttestationMissing,
	BlockerLiveContainerIdentityNotObserved,
	BlockerLiveQuiesceNotAuthorized,
	BlockerStateWriterQuiesceUnproven,
	BlockerProbeStatePathBindingUnproven,
	BlockerExternalTimeAnchorMissing,
}

type ConfigurationDigests struct {
	ProbeEnvSHA256     string
	CatalogSHA256      string
	CatalogDigest      string
	DotCASHA256        string
	EgressPolicySHA256 string
}

type LocalReleaseDigests struct {
	ComposeSourceSHA256    string
	ComposeRenderedSHA256  string
	RenderedSemanticSHA256 string
	LocalBindingSHA256     string
}

// Observation contains only redacted facts. It intentionally has no JSON
// tags and no exported fields: v1 is an in-process diagnostic API, not a
// persisted trust contract.
type Observation struct {
	schema             string
	boundary           string
	authorization      string
	instance           string
	candidateID        string
	identityGeneration uint64
	identitySHA256     string
	projectName        string
	serviceName        string
	candidateRoot      string
	stateMountTarget   string
	bootID             string
	observedUnix       int64
	observedBoottimeNS uint64
	configuration      ConfigurationDigests
	localRelease       LocalReleaseDigests
	blockers           []BlockerCode
}

func (o Observation) Schema() string                      { return o.schema }
func (o Observation) Boundary() string                    { return o.boundary }
func (o Observation) Authorization() string               { return o.authorization }
func (o Observation) Instance() string                    { return o.instance }
func (o Observation) CandidateID() string                 { return o.candidateID }
func (o Observation) IdentityGeneration() uint64          { return o.identityGeneration }
func (o Observation) IdentitySHA256() string              { return o.identitySHA256 }
func (o Observation) ProjectName() string                 { return o.projectName }
func (o Observation) ServiceName() string                 { return o.serviceName }
func (o Observation) CandidateRoot() string               { return o.candidateRoot }
func (o Observation) StateMountTarget() string            { return o.stateMountTarget }
func (o Observation) BootID() string                      { return o.bootID }
func (o Observation) ObservedUnix() int64                 { return o.observedUnix }
func (o Observation) ObservedBoottimeNS() uint64          { return o.observedBoottimeNS }
func (o Observation) Configuration() ConfigurationDigests { return o.configuration }
func (o Observation) LocalRelease() LocalReleaseDigests   { return o.localRelease }
func (o Observation) Blockers() []BlockerCode             { return append([]BlockerCode(nil), o.blockers...) }

// Handle owns all process-local capabilities used by one observation. Copies
// share one lifecycle so aliases cannot release locks twice.
type Handle struct{ control *handleControl }

type handleControl struct {
	mu       sync.Mutex
	lease    *restorelease.Lease
	clock    *restoreclock.Clock
	start    restoreclock.Snapshot
	platform *platformSnapshot
	value    Observation
	closed   bool
	poisoned bool
}

// OpenAdvisory acquires a Linux lifecycle lease and reads only the fixed
// candidate configuration objects. It intentionally does not inspect probe
// state: there is no trusted live-container observation or quiesce authority
// in this package. It never stops a process or container.
func OpenAdvisory(candidateRoot string) (*Handle, error) {
	return openAdvisory(candidateRoot, observationConfig)
}

// OpenIdentityBound additionally binds a root-owned local identity file. The
// file is not an external attestation, so every trust blocker remains present.
// The result does not prove Compose, image, runtime, quiesce, state, or time.
func OpenIdentityBound(candidateRoot string) (*Handle, error) {
	return openAdvisory(candidateRoot, observationIdentity)
}

// OpenReleaseBound additionally binds local evidence copies of the active-probe
// Compose source, rendered JSON, and their local binding receipt. These objects
// remain self-asserted inside the candidate root: they are not provenance,
// renderer, image, or runtime attestations and remove no blockers.
func OpenReleaseBound(candidateRoot string) (*Handle, error) {
	return openAdvisory(candidateRoot, observationRelease)
}

type observationMode uint8

const (
	observationConfig observationMode = iota
	observationIdentity
	observationRelease
)

func openAdvisory(candidateRoot string, mode observationMode) (*Handle, error) {
	if mode > observationRelease {
		return nil, ErrInvalid
	}
	instance, err := candidateInstance(candidateRoot)
	if err != nil {
		return nil, err
	}
	lease, err := restorelease.Acquire(candidateRoot)
	if err != nil {
		if errors.Is(err, restorelease.ErrUnsupported) {
			return nil, ErrUnsupported
		}
		return nil, fmt.Errorf("acquire restore current lease: %w", err)
	}
	control := &handleControl{lease: lease}
	fail := func(cause error) (*Handle, error) {
		return nil, errors.Join(cause, control.closeLocked())
	}
	clock, start, err := restoreclock.Open()
	if err != nil {
		if errors.Is(err, restoreclock.ErrUnsupported) {
			return fail(ErrUnsupported)
		}
		return fail(fmt.Errorf("open restore current clock: %w", err))
	}
	control.clock, control.start = clock, start
	if err := lease.Verify(); err != nil {
		return fail(fmt.Errorf("verify restore current lease: %w", err))
	}
	platform, contents, err := openPlatform(candidateRoot, lease.Identity(), mode)
	if err != nil {
		return fail(err)
	}
	control.platform = platform
	defer clear(contents.env)
	defer clear(contents.identity)
	defer clear(contents.composeSource)
	defer clear(contents.composeJSON)
	defer clear(contents.composeBinding)
	env, err := validateConfiguration(contents, candidateRoot, instance)
	if err != nil {
		return fail(err)
	}
	catalog, err := parseCandidateCatalog(contents.catalog)
	if err != nil {
		return fail(err)
	}
	if err := control.verifyResourcesLocked(); err != nil {
		return fail(err)
	}
	end, err := clock.ObserveWithin(start, observationWindow, observationMaximumDrift)
	if err != nil {
		return fail(fmt.Errorf("close restore current observation window: %w", err))
	}
	identity := candidateIdentity{}
	identityDigest := ""
	if mode >= observationIdentity {
		identity, err = parseCandidateIdentity(contents.identity, candidateRoot, instance, env.projectName)
		if err != nil {
			return fail(err)
		}
		identityDigest = digest(contents.identity)
	}
	releaseDigests := LocalReleaseDigests{}
	if mode == observationRelease {
		releaseDigests, err = validateLocalRelease(contents, env, identity)
		if err != nil {
			return fail(err)
		}
	}
	blockerSource := mandatoryBlockers
	schema := ObservationSchemaV1
	boundary := "ADVISORY_CONFIG_BOUND"
	if mode >= observationIdentity {
		schema = IdentityObservationSchemaV1
		boundary = "ADVISORY_LOCAL_IDENTITY_BOUND"
	}
	if mode == observationRelease {
		schema = ReleaseObservationSchemaV1
		boundary = "ADVISORY_LOCAL_RELEASE_BOUND"
	}
	blockers := append([]BlockerCode(nil), blockerSource...)
	sort.Slice(blockers, func(i, j int) bool { return blockers[i] < blockers[j] })
	control.value = Observation{
		schema: schema, boundary: boundary, authorization: "BLOCKED", instance: instance,
		candidateID: identity.CandidateID, identityGeneration: identity.IdentityGeneration,
		identitySHA256: identityDigest,
		projectName:    env.projectName, serviceName: serviceName, candidateRoot: candidateRoot,
		stateMountTarget: stateMountTarget, bootID: end.BootID(), observedUnix: end.WallUTC().Unix(),
		observedBoottimeNS: end.BoottimeNS(), blockers: blockers,
		configuration: ConfigurationDigests{
			ProbeEnvSHA256: digest(contents.env), CatalogSHA256: digest(contents.catalog),
			CatalogDigest: catalog.Digest, DotCASHA256: digest(contents.ca),
			EgressPolicySHA256: digest(contents.policy),
		},
		localRelease: releaseDigests,
	}
	return &Handle{control: control}, nil
}

// Observation re-verifies every held capability before returning an immutable
// copy. A verification failure permanently poisons the handle.
func (h *Handle) Observation() (Observation, error) {
	if h == nil || h.control == nil {
		return Observation{}, ErrClosed
	}
	c := h.control
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return Observation{}, ErrClosed
	}
	if c.poisoned {
		return Observation{}, ErrPoisoned
	}
	if err := c.verifyLocked(); err != nil {
		return Observation{}, err
	}
	copy := c.value
	copy.blockers = append([]BlockerCode(nil), c.value.blockers...)
	return copy, nil
}

func (h *Handle) Verify() error {
	if h == nil || h.control == nil {
		return ErrClosed
	}
	c := h.control
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return ErrClosed
	}
	if c.poisoned {
		return ErrPoisoned
	}
	return c.verifyLocked()
}

func (c *handleControl) verifyLocked() error {
	if err := c.verifyResourcesLocked(); err != nil {
		c.poisoned = true
		return errors.Join(ErrPoisoned, err)
	}
	if _, err := c.clock.ObserveWithin(c.start, observationWindow, observationMaximumDrift); err != nil {
		c.poisoned = true
		return errors.Join(ErrPoisoned, err)
	}
	return nil
}

func (c *handleControl) verifyResourcesLocked() error {
	if c.lease == nil || c.platform == nil {
		return ErrInvalid
	}
	if err := c.lease.Verify(); err != nil {
		return fmt.Errorf("verify lifecycle lease: %w", err)
	}
	if err := c.platform.verify(); err != nil {
		return fmt.Errorf("verify held candidate objects: %w", err)
	}
	if err := c.lease.Verify(); err != nil {
		return fmt.Errorf("reverify lifecycle lease: %w", err)
	}
	return nil
}

func (h *Handle) Close() error {
	if h == nil || h.control == nil {
		return nil
	}
	c := h.control
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeLocked()
}

func (c *handleControl) closeLocked() error {
	if c.closed {
		return nil
	}
	c.closed = true
	var err error
	if c.platform != nil {
		err = errors.Join(err, c.platform.close())
		c.platform = nil
	}
	if c.lease != nil {
		err = errors.Join(err, c.lease.Close())
		c.lease = nil
	}
	return err
}

func candidateInstance(candidateRoot string) (string, error) {
	if candidateRoot == "" || !strings.HasPrefix(candidateRoot, "/") || path.Clean(candidateRoot) != candidateRoot || strings.ContainsAny(candidateRoot, "\\\x00") {
		return "", errors.Join(ErrInvalid, errors.New("candidate root must be a clean absolute POSIX path"))
	}
	for _, base := range []string{"/var/lib/chengwang-m2b-candidate", "/srv/chengwang-m2b-candidate"} {
		if path.Dir(candidateRoot) == base && safeInstance.MatchString(path.Base(candidateRoot)) {
			return path.Base(candidateRoot), nil
		}
	}
	return "", errors.Join(ErrInvalid, errors.New("candidate root is outside the fixed production namespace"))
}

func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func parseCandidateCatalog(raw []byte) (probe.Catalog, error) {
	catalog, err := probe.ParseCatalogBytes(raw)
	if err != nil {
		return probe.Catalog{}, errors.Join(ErrInvalid, errors.New("candidate catalog is invalid"))
	}
	return catalog, nil
}
