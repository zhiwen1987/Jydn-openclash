# Continuous Recovery identity-profile structural fence design card

Date: 2026-10-26 Asia/Shanghai

Snapshot: `6e309c4d150b6f9248089ad50abf3ede9015784c`

## Finding

The current successful-output contract is structurally unsatisfiable. This is a source-proven namespace collision, not evidence that a credential leaked and not a request to identify the hidden CI value.

The proof is independent of the private receipt:

1. `LabObjectType` is a fixed public protocol discriminator.
2. The continuous Go harness puts that discriminator into `scope.ObjectType`, then serializes the scope inside every identity's `principal.allowedScopes` in the private v1 authn profile.
3. `build_forbidden` gives only `allowedScopes[].environment` and `roles[]` special path classes. `allowedScopes[].objectType` is therefore `IDENTITY_PROFILE/JSON_OTHER_SCALAR` and receives the RAW plus seven encoded variants.
4. Successful API DTO schema constants embed the same public discriminator in head, deployment, candidate, recovery, and acceptance schema names. The independent checker requires those exact schemas, and the worker exports the original response bytes.
5. `fence_outputs` rejects any output containing any forbidden representation of length at least eight. Therefore an otherwise valid 31-response PASS must hit the phase-one report/originals fence.

Changing actor metadata could solve the earlier role collision, but cannot solve this one. Renaming one field or guessing another alias merely moves a protocol-wide collision and does not repair the mixed-confidentiality model.

## Invariant conflict

Let `x` be a scalar classified as secret by the private-input inventory. The current fence requires `x` not to occur byte-for-byte in any exported output. The current originals contract simultaneously requires exporting an unchanged response that necessarily contains `x`. These requirements cannot both be true.

With value/path allowlists, masking, secret-derived encoding, weaker length thresholds, and loss of original bytes forbidden, one of the following structural boundaries must change:

- remove public authorization metadata from the private credential input; or
- keep original responses inside the private verification boundary and export only a safe verification receipt.

There is no third byte-preserving fence-only fix.

## Recommended contract: bound credentials v2

Use a new, isolated-test-only credential input contract. Do not reinterpret or partially exempt the existing authn v1 file.

### Private credential file

The private file contains credential facts only:

- exact versioned schema;
- opaque token identifier;
- token hash;
- one closed binding selector;
- disabled/not-before/expires-at state.

It contains no principal ID, tenant, site, object type, object ID, environment, or role text. The existing plaintext-token file and TLS/service/config secret inputs remain unchanged.

The complete credential file and every scalar remain in the private inventory and continue to produce all eight representations. `encoded_secret_variants`, substring matching, the minimum-length rule, and both fence phases remain byte-for-byte unchanged. A token, hash, identifier, or other credential scalar equal to any public protocol value must still reject the export.

### Trusted authorization binding

A new explicit authn entry point, rather than the existing `authn.Open` v1 path, joins an authenticated credential to a closed, source-bound binding table. This is proposed work; no such production service exists in the inspected snapshot.

For this isolated lane only, the table constructs synthetic principals from:

- the existing fixed five-role set;
- the harness's fixed synthetic tenant/site/object identity;
- `LabObjectType` and `LabEnvironment` from source;
- the existing management object binding.

The credential chooses only a known binding selector; it cannot supply or override any principal, role, tenant, site, object, or environment field. Unknown, duplicate, missing, disabled, premature, expired, or extra bindings fail before the first request. The table must reject external/customer identifiers and any environment-derived arbitrary principal metadata in this lane.

Bearer verification remains the real constant-time token-hash path. The resulting `authz.Principal` still passes through the current `authz.Evaluate` scope/action checks. This preserves real authentication, tenant/site/object isolation, role separation, expiry/revocation behavior, and the 31 CASE-to-request-role mapping without placing public protocol vocabulary in a secret input.

### Compatibility boundary

- Keep authn v1 unchanged for existing consumers.
- The continuous lane must opt in to bound-credentials v2 explicitly; no automatic v1 fallback.
- A v1 profile presented to this lane, a v2 file containing principal/scope/role fields, or an unknown schema is rejected before runtime/request dispatch.
- Do not call the authorization table a credential store. It is integrity-sensitive, source-bound test policy, not secret material and not caller authority by itself.

## Evidence and checker contract

The report and `http-NNN.response.json` files remain the exact observed bytes; no redaction, normalization, re-encoding, or reconstructed DTO is substituted.

The report/index remain schema v2 unless implementation needs a version bump to bind the new authn input mode. If bumped, worker, checker, contract, model, workflow, and fresh consumer must reject all older/unknown combinations rather than accept both ambiguously.

The independent checker must retain:

- exact source commit/tree/working-byte binding;
- PASS/NONE and exactly 31 ordered cases;
- CASE to real request role to fixed public actor mapping;
- 26 successful 200 responses and 5 successful 201 responses;
- original response byte/hash/index equality;
- exact common envelopes and full business DTO/head/recovery/cleanup relations;
- true runtime head, COMPLETED/UNKNOWN transitions, and owned cleanup gates.

The worker still runs the report/originals fence first and the all-output fence second. Fresh verification still consumes only artifacts that passed both fences.

## Required negative coverage

1. Legacy v1, unknown schema, unknown/duplicate/missing binding, extra identity, and arbitrary principal/scope/role fields all fail before request dispatch.
2. Swapped credential-to-binding selectors cannot produce a successful chain; endpoint RBAC and the fixed CASE mapping must fail closed.
3. Disabled, not-yet-valid, expired, and atomically replaced credential snapshots retain current authn behavior.
4. Tenant, site, object type, object ID, environment, and role cannot be supplied by the credential file or HTTP caller.
5. Every private credential class and all eight variants collide in each fence phase when inserted into an output.
6. A genuine credential scalar equal to a public schema, boundary, actor, case, or other public constant still rejects. There is no public-value exception.
7. Whole-private-file collision remains rejected.
8. Exact 31 raw originals, response hashes, index bindings, status distribution, common envelopes, business state, source HEAD, and cleanup remain checker/fresh requirements.
9. No failure diagnostic may print the selector input, token ID, hash, token, principal, URL, body, digest, or offset.

## Rejected alternatives

- No value, path, role, scope, schema-fragment, or output-name allowlist in `fence_outputs`.
- No masking, replacement, hashing-as-a-substitute, compression, encryption, base64-only export, or other secret-derived transform of original HTTP bytes.
- No larger global minimum length and no removal of JSON scalar recursion, whole-file inventory, or either fence phase.
- No object-type/schema rename or per-collision alias chase.
- No claim that a passing report proves the private profile, full private WAL, internet business traffic, or production.

## Fallback if authn input cannot change

Keep the current identity profile and all inventory rules, but move the exact raw responses and the independent checker into a private evidence domain. Export only a separately fenced bounded verification receipt. This preserves unchanged raw evidence internally, but it is a materially different acceptance product: the current `httpOriginalBytesRequired=true` contract, public originals artifact, and cross-job fresh replay would need a new version and could no longer claim publicly downloadable original bytes.

This fallback must not describe a CI artifact, filesystem copy, hash chain, append-only file, or independent copy as WORM. WORM requires independently configured and verified retention/object-lock controls and recovery authority, none of which this snapshot proves.

## Exit conditions for an implementation candidate

- Exact source review shows no private principal/scope/role fields in the v2 credential serialization and no arbitrary input into the binding table.
- Existing authn v1 behavior is unchanged outside the explicitly selected isolated lane.
- Secret inventory and both fence functions are byte-identical, or any unavoidable mechanical signature change is proven semantically identical by source hashes and exhaustive negative tests.
- Pure model tests cover all failures above.
- Authorized Go tests prove real bearer authentication and RBAC for all 31 cases; this design review does not.
- A fresh CI run produces the complete 31-response PASS, crosses both fences without exemptions, and passes the original independent checker and fresh consumer.
- No real private value is printed or retained in public diagnostics.

## Review boundary

This was read-only source analysis. No Go, gofmt, CI, runtime/network, download, private artifact, credential, production system, or repository mutation was used. No external reference was needed because the contradiction and viable boundaries are fully determined by the local source contracts.

## Integration review addendum: design only

The original design card above is retained as the source analysis, not as an implemented capability. Subsequent independent review found two consumers that must be handled together: `RunWith` opens the API's immutable `authn.Store`, and `OpenMihomoLabRuntime` opens a freshness-checking `authn.SnapshotManager`. Changing only one leaves an incompatible v1 consumer; opening the v2 input twice independently can create inconsistent startup observations.

An implementation candidate must therefore define one startup bundle with a stable credential read, a common source-bound principal table, and the same initial credential digest for both consumers. Subsequent manager reads must continue checking the real v2 file and retain existing epoch retirement, revocation, clock, and close behavior. The API store's existing static semantics must not silently be presented as dynamic revocation.

Activation must be limited to the exact isolated continuous-fault build tags and the process-local source-issued arm. Other tag combinations use the strict complement and existing v1 path. No HTTP, environment, public `Options` callback, or caller-supplied binding table can enable this lane. An armed lane must reject v1 rather than fall back. Token identifiers and selectors must have an exact source-issued pairing and completeness check; a selector merely belonging to an enum is insufficient.

These are candidate acceptance requirements. No bound-credentials implementation, new Linux pass, or product deployment is claimed here. The actual 6e309 run still failed before public originals export.

For context, GitHub's [official Actions security guidance](https://docs.github.com/en/actions/reference/security/secure-use) warns that structured secrets and derived values are not reliably covered by automatic log redaction. That supports retaining explicit per-value checks and both output fences; it does not prove this proposed architecture or authorize a metadata exception.
