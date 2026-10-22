// Package binding joins authenticated approval, a live Registry readback and
// standard Sigstore verification. It never grants deployment/recovery authority.
package binding

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"time"

	verifier "chengwang-image-verifier"
	"chengwang/image-binding/policy"
	"chengwang/image-binding/registry"
)

var ErrInvalid = errors.New("image provenance binding rejected")

const Boundary = "ADVISORY_APPROVED_REGISTRY_SIGNATURE_BOUND"

// Result only contains hash/public identity projections of this process's
// actual reads and verifications. An external receipt cannot mint this type.
type Result struct {
	verified                                               bool
	reference, approvalSHA256, graphSHA256                 string
	manifestSHA256, configSHA256, bundleSHA256, rootSHA256 string
	registryHost, policyID, approverKeyID                  string
	policyRevision                                         uint64
	observedAt                                             time.Time
}

func (r Result) Verified() bool { return r.verified }
func (r Result) Boundary() string {
	if !r.verified {
		return ""
	}
	return Boundary
}
func (r Result) Authorization() string     { return "BLOCKED" }
func (r Result) Reference() string         { return r.reference }
func (r Result) ApprovalSHA256() string    { return r.approvalSHA256 }
func (r Result) GraphSHA256() string       { return r.graphSHA256 }
func (r Result) ManifestSHA256() string    { return r.manifestSHA256 }
func (r Result) ConfigSHA256() string      { return r.configSHA256 }
func (r Result) BundleSHA256() string      { return r.bundleSHA256 }
func (r Result) TrustedRootSHA256() string { return r.rootSHA256 }
func (r Result) RegistryHost() string      { return r.registryHost }
func (r Result) PolicyID() string          { return r.policyID }
func (r Result) PolicyRevision() uint64    { return r.policyRevision }
func (r Result) ApproverKeyID() string     { return r.approverKeyID }
func (r Result) ObservedAt() time.Time     { return r.observedAt }

// Bind re-verifies approval in this call rather than importing client-provided
// success booleans or observations. Signature verification precedes Registry
// access, so an invalid bundle never triggers outbound requests. roots and
// bearerToken are separately supplied transport trust/credentials, not policy
// fields and are never returned. Use external process resource/time limits.
func Bind(ctx context.Context, trust policy.Trust, approvalRaw, bundleRaw, rootRaw []byte, roots *x509.CertPool, bearerToken string) (Result, error) {
	if ctx == nil {
		return Result{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if len(approvalRaw) == 0 || len(approvalRaw) > policy.MaxEnvelopeBytes || len(bundleRaw) == 0 || len(bundleRaw) > verifier.MaxBundleBytes || len(rootRaw) == 0 || len(rootRaw) > verifier.MaxRootBytes {
		return Result{}, ErrInvalid
	}
	approvalRaw, bundleRaw, rootRaw = bytes.Clone(approvalRaw), bytes.Clone(bundleRaw), bytes.Clone(rootRaw)
	approval, err := policy.Verify(ctx, trust, approvalRaw, time.Now())
	if err != nil {
		return reject(ctx)
	}
	sig, err := verifier.Verify(ctx, approval.SignatureExpected(), bundleRaw, rootRaw)
	if err != nil || !sig.Verified() || sig.Authorization() != "BLOCKED" {
		return reject(ctx)
	}
	if !approval.ValidAt(time.Now()) {
		return Result{}, ErrInvalid
	}
	observation, err := registry.Read(ctx, approval, roots, bearerToken)
	if err != nil || !observation.Verified() {
		return reject(ctx)
	}
	graph := observation.Graph()
	content := graph.Content()
	if !approval.ValidAt(time.Now()) || observation.ApprovalSHA256() != approval.SHA256() || observation.Reference() != approval.Reference() || content.Reference() != approval.Reference() || content.ManifestDigest() != sig.ArtifactSHA256() || content.OS() != approval.OS() || content.Architecture() != approval.Architecture() || content.Variant() != approval.Variant() || sig.TrustedRootSHA256() != approval.SignatureExpected().TrustedRootSHA256 || graph.GraphSHA256() == "" || observation.ObservedAt().IsZero() {
		return Result{}, ErrInvalid
	}
	// Bind the exact validated materials; do not expose raw certificates,
	// policy bytes, config Env/history, layer data or Registry credentials.
	hash := sha256.Sum256(bundleRaw)
	if sig.BundleSHA256() != "sha256:"+hex.EncodeToString(hash[:]) {
		return Result{}, ErrInvalid
	}
	if ctx.Err() != nil {
		return reject(ctx)
	}
	if !approval.ValidAt(time.Now()) {
		return Result{}, ErrInvalid
	}
	return Result{
		verified: true, reference: content.Reference(), approvalSHA256: approval.SHA256(), graphSHA256: graph.GraphSHA256(),
		manifestSHA256: content.ManifestDigest(), configSHA256: content.ConfigDigest(), bundleSHA256: sig.BundleSHA256(), rootSHA256: sig.TrustedRootSHA256(),
		registryHost: observation.RegistryHost(), policyID: approval.ID(), policyRevision: approval.Revision(), approverKeyID: approval.KeyID(), observedAt: observation.ObservedAt(),
	}, nil
}

func reject(ctx context.Context) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	return Result{}, ErrInvalid
}
