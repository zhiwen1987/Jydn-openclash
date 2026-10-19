package restoreimage

import (
	"regexp"
	"sort"

	"chengwang/internal/restorecurrent"
	"chengwang/internal/restoreruntime"
)

var candidateIDPattern = regexp.MustCompile(`^candidate-[0-9a-f]{32}$`)

const (
	AssociationSchemaV1  = "chengwang.restore-local-image-association/v1"
	AssociationBoundary  = "ADVISORY_LOCAL_IMAGE_ASSOCIATION"
	AuthorizationBlocked = "BLOCKED"
)

// Association is a process-local diagnostic result. No exported constructor or
// JSON decoder can manufacture an accepted runtime observation. Successful
// association retains every independent trust and restore authorization gate.
type Association struct {
	schema, boundary, authorization                         string
	reference, manifestDigest, configDigest, runtimeImageID string
	candidateID, containerID, runtimeSHA256                 string
	blockers                                                []restorecurrent.BlockerCode
}

func (a Association) Schema() string         { return a.schema }
func (a Association) Boundary() string       { return a.boundary }
func (a Association) Authorization() string  { return a.authorization }
func (a Association) Reference() string      { return a.reference }
func (a Association) ManifestDigest() string { return a.manifestDigest }
func (a Association) ConfigDigest() string   { return a.configDigest }
func (a Association) RuntimeImageID() string { return a.runtimeImageID }
func (a Association) CandidateID() string    { return a.candidateID }
func (a Association) ContainerID() string    { return a.containerID }
func (a Association) RuntimeSHA256() string  { return a.runtimeSHA256 }
func (a Association) Blockers() []restorecurrent.BlockerCode {
	return append([]restorecurrent.BlockerCode(nil), a.blockers...)
}

// BindLocal associates validated config bytes with the image ID in one opaque
// P0-c observation. The observation records a past local sample; this function
// cannot establish present liveness, repository ownership, RepoDigests, layer
// contents, signatures, or whether Compose deploys an immutable reference.
func BindLocal(content Content, runtime restoreruntime.Observation) (Association, error) {
	return bindFacts(content, factsFromRuntime(runtime))
}

type runtimeFacts struct {
	schema, boundary, authorization                  string
	candidateID, containerID, imageID, runtimeSHA256 string
	blockers                                         []restorecurrent.BlockerCode
}

func factsFromRuntime(runtime restoreruntime.Observation) runtimeFacts {
	return runtimeFacts{
		schema: runtime.Schema(), boundary: runtime.Boundary(), authorization: runtime.Authorization(),
		candidateID: runtime.CandidateID(), containerID: runtime.ContainerID(),
		imageID: runtime.ImageID(), runtimeSHA256: runtime.RuntimeSHA256(), blockers: runtime.Blockers(),
	}
}

func bindFacts(content Content, runtime runtimeFacts) (Association, error) {
	if content.boundary != ContentBoundary || !digestPattern.MatchString(content.manifestDigest) ||
		!digestPattern.MatchString(content.configDigest) || !validPlatform(content.os, content.architecture, content.variant) ||
		content.layerCount < 1 || content.layerCount > maximumLayers {
		return Association{}, ErrInvalid
	}
	digest, valid := referenceDigest(content.reference)
	if !valid || digest != content.manifestDigest || runtime.schema != restoreruntime.ObservationSchemaV1 ||
		runtime.boundary != restoreruntime.ObservationBoundary || runtime.authorization != AuthorizationBlocked ||
		!candidateIDPattern.MatchString(runtime.candidateID) || !digestPattern.MatchString(runtime.runtimeSHA256) ||
		!digestPattern.MatchString("sha256:"+runtime.containerID) || runtime.imageID != content.configDigest ||
		!exactBlockers(runtime.blockers) {
		return Association{}, ErrInvalid
	}
	blockers := append([]restorecurrent.BlockerCode(nil), runtime.blockers...)
	sort.Slice(blockers, func(i, j int) bool { return blockers[i] < blockers[j] })
	return Association{
		schema: AssociationSchemaV1, boundary: AssociationBoundary, authorization: AuthorizationBlocked,
		reference: content.reference, manifestDigest: content.manifestDigest,
		configDigest: content.configDigest, runtimeImageID: runtime.imageID,
		candidateID: runtime.candidateID, containerID: runtime.containerID,
		runtimeSHA256: runtime.runtimeSHA256, blockers: blockers,
	}, nil
}

func exactBlockers(values []restorecurrent.BlockerCode) bool {
	want := []restorecurrent.BlockerCode{
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
	if len(values) != len(want) {
		return false
	}
	seen := make(map[restorecurrent.BlockerCode]bool, len(values))
	for _, code := range values {
		if seen[code] {
			return false
		}
		seen[code] = true
	}
	for _, code := range want {
		if !seen[code] {
			return false
		}
	}
	return true
}
