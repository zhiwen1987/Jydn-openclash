package binding

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"

	verifier "chengwang-image-verifier"
	"chengwang/image-binding/policy"
	"chengwang/image-binding/truststate"
)

var ErrManagedInvalid = errors.New("managed image binding rejected")

const ManagedBoundary = "ADVISORY_MANAGED_REGISTRY_SIGNATURE_BOUND"

// ManagedResult records a successful verification and durable single-use grant
// consumption. It is neither a deployment permission nor a reusable ticket.
// It cannot be imported from JSON. Low-level Bind results cannot construct it.
type ManagedResult struct {
	managed    bool
	binding    Result
	grant      string
	catalogue  string
	generation uint64
	evidence   string
	validUntil int64
}

func (r ManagedResult) Verified() bool { return r.managed && r.binding.Verified() }
func (r ManagedResult) Boundary() string {
	if !r.Verified() {
		return ""
	}
	return ManagedBoundary
}
func (r ManagedResult) Authorization() string       { return "BLOCKED" }
func (r ManagedResult) Binding() Result             { return r.binding }
func (r ManagedResult) GrantID() string             { return r.grant }
func (r ManagedResult) CatalogueSHA256() string     { return r.catalogue }
func (r ManagedResult) CatalogueGeneration() uint64 { return r.generation }
func (r ManagedResult) EvidenceSHA256() string      { return r.evidence }

// ValidUntilUnix is the earlier authenticated approval/catalogue expiry.
// It does not make an old result immune to subsequent catalogue revocation.
func (r ManagedResult) ValidUntilUnix() int64 { return r.validUntil }

// ManagedBind resolves approval trust from a separately bootstrapped Store,
// durably burns its signed grant before external work, and rechecks current
// trust/revocation/expiry in the final consumption transaction. A failed or
// canceled attempt never unburns its grant. Callers must not mutate roots or
// input slices concurrently. Cryptographic verification still requires external
// process hard limits: context cancellation cannot interrupt every SDK call.
func ManagedBind(ctx context.Context, store *truststate.Store, policyID string, approvalRaw, bundleRaw, rootRaw []byte, roots *x509.CertPool, bearerToken string) (ManagedResult, error) {
	return managedBind(ctx, store, "", policyID, approvalRaw, bundleRaw, rootRaw, roots, bearerToken, nil)
}

// ManagedBindTracked uses a durable product intent and optional independently
// enforced refresh freshness bound. The older low-level API remains advisory
// and does not acquire journal authority by importing a receipt.
func ManagedBindTracked(ctx context.Context, store *truststate.Store, opID, policyID string, approvalRaw, bundleRaw, rootRaw []byte, roots *x509.CertPool, bearerToken string, bound *truststate.SourceBound) (ManagedResult, error) {
	if opID == "" {
		return ManagedResult{}, ErrManagedInvalid
	}
	return managedBind(ctx, store, opID, policyID, approvalRaw, bundleRaw, rootRaw, roots, bearerToken, bound)
}

func managedBind(ctx context.Context, store *truststate.Store, opID, policyID string, approvalRaw, bundleRaw, rootRaw []byte, roots *x509.CertPool, bearerToken string, bound *truststate.SourceBound) (ManagedResult, error) {
	if ctx == nil {
		return ManagedResult{}, ErrManagedInvalid
	}
	fail := func() (ManagedResult, error) {
		if err := ctx.Err(); err != nil {
			return ManagedResult{}, err
		}
		return ManagedResult{}, ErrManagedInvalid
	}
	if ctx.Err() != nil || store == nil || len(approvalRaw) == 0 || len(approvalRaw) > policy.MaxEnvelopeBytes || len(bundleRaw) == 0 || len(bundleRaw) > verifier.MaxBundleBytes || len(rootRaw) == 0 || len(rootRaw) > verifier.MaxRootBytes {
		return fail()
	}
	approvalRaw, bundleRaw, rootRaw = bytes.Clone(approvalRaw), bytes.Clone(bundleRaw), bytes.Clone(rootRaw)
	var ticket truststate.Ticket
	var err error
	if opID != "" {
		ticket, err = store.BeginTracked(ctx, policyID, approvalRaw, opID, bound)
	} else {
		ticket, err = store.Begin(ctx, policyID, approvalRaw)
	}
	if err != nil {
		return fail()
	}
	result, err := Bind(ctx, ticket.Trust(), approvalRaw, bundleRaw, rootRaw, roots, bearerToken)
	if err != nil || !result.Verified() || result.Authorization() != "BLOCKED" || result.PolicyID() != policyID || result.ManifestSHA256() != ticket.ManifestSHA256() {
		return fail()
	}
	// Only public identifiers and digests are committed. No Registry token,
	// config, bundle, private key, or transport error becomes ledger content.
	projection := struct {
		Schema, Grant, Catalogue                                   string
		Generation                                                 uint64
		Reference, Approval, Manifest, Config, Graph, Bundle, Root string
		ObservedAtUnixNano                                         int64
		ValidUntilUnix                                             int64
	}{
		"chengwang.managed-binding-evidence/v1", ticket.GrantID(), ticket.CatalogueSHA256(), ticket.Generation(),
		result.Reference(), result.ApprovalSHA256(), result.ManifestSHA256(), result.ConfigSHA256(), result.GraphSHA256(), result.BundleSHA256(), result.TrustedRootSHA256(), result.ObservedAt().UnixNano(),
		ticket.ValidUntilUnix(),
	}
	raw, err := json.Marshal(projection)
	if err != nil {
		return fail()
	}
	hash := sha256.Sum256(raw)
	evidence := "sha256:" + hex.EncodeToString(hash[:])
	if ctx.Err() != nil {
		return fail()
	}
	if err := store.Complete(ctx, ticket, evidence); err != nil || ctx.Err() != nil {
		return fail()
	}
	return ManagedResult{true, result, ticket.GrantID(), ticket.CatalogueSHA256(), ticket.Generation(), evidence, ticket.ValidUntilUnix()}, nil
}
