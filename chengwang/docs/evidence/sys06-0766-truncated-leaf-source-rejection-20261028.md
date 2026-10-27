# Independent truncated build-location protocol source review

Verdict: **REVISE**

- Base: `0766c7f7475b5e31633d6093e952d0d360872d4d`
- Exact patch: 19,431 bytes
- Patch SHA-256: `28591799379e1f05a8a15e84996129974acfa7cfa7681405384b1696b29158b0`

## Blocking finding

The patch renames the model test method from `test_more_than_eight_locations_and_oversized_stderr_are_unknown` to `test_more_than_eight_locations_are_deterministically_truncated_only_after_full_validation`, but the workflow still pins the prior 61-name digest.

Applying the exact AST inventory code embedded in workflow lines 60–70 to the frozen candidate yields:

`49798156a48c101db44e8affd441b6e97f2ea5d17f7ab2aba6fa55494f495de0`

The workflow still requires:

`1093918bbaafd00a40b06a4d7e9856126a89a18c53cf7ff2d9a52864170b48bd`

Therefore the `source-models` job deterministically fails its inline assertion before the downstream lane. The manifest statement `sourceModelTopNamesChanged: 0` is also false.

Minimal correction: retain the old method name while replacing its body, which restores the old digest and keeps the test-top contract unchanged. Alternatively update the workflow digest and manifest truthfully, but the rename has no functional need.

## Other reviewed boundaries

No second defect was found in the truncation algorithm. It stores at most eight locations, continues scanning the full bounded stderr, returns UNKNOWN with an empty location list for later foreign, malformed, control, UTF-8, range, line, or input failures, and emits TRUNCATED/LOCATION_COUNT_OVERFLOW/OVER8/true only after all input is valid. Ordering is deterministic and duplicates do not create overflow. Whole-object private-input reprojection, privacy boundaries, and final/fresh acceptance gates remain strict.

The separate Go helper type mismatch reported to root is a base-source issue and is not counted as a finding against this frozen three-path patch.

Boundary: source-only review. No Go, gofmt, Linux workflow, browser, service, or production action was run; the supplied 61 models were not repeated.

```json
{
  "schemaVersion": 1,
  "patch": {
    "repository": "D:/CodexData/workspace/mihomo-0766-build-location-truncated-20261028-implementation56h-v1/repo",
    "sourceType": "patch_file",
    "base": "0766c7f7475b5e31633d6093e952d0d360872d4d",
    "head": "working-tree-afterimage-truncated-v1",
    "changedFiles": [
      ".github/workflows/chengwang-subscription-refresh.yml",
      "chengwang/deploy/subscription-refresh/check_go_failure.py",
      "chengwang/deploy/subscription-refresh/test_go_failure.py"
    ],
    "sha256": "28591799379e1f05a8a15e84996129974acfa7cfa7681405384b1696b29158b0"
  },
  "recommendation": "revise",
  "workflowLabel": "revise",
  "impact": {
    "rating": "moderate",
    "rationale": "The defect deterministically breaks the source-models workflow gate, blocking CI for an otherwise diagnostic-only patch."
  },
  "regressionLikelihood": {
    "rating": "high",
    "rationale": "The candidate AST inventory digest is 49798156a48c101db44e8affd441b6e97f2ea5d17f7ab2aba6fa55494f495de0 while the workflow asserts the old 1093918b digest."
  },
  "regressionProtection": {
    "rating": "partial",
    "rationale": "The inline workflow assertion would detect the mismatch, but the supplied 61-unit-test and source-check evidence did not execute that exact inline inventory assertion.",
    "exactHeadChecksPassed": false
  },
  "recoverability": {
    "rating": "easy",
    "rationale": "Restore the original test method name or update the bound workflow digest and manifest; no product state is involved."
  },
  "confidence": {
    "rating": "high",
    "rationale": "The exact workflow algorithm was independently reproduced against the frozen afterimage, and the renamed method is visible in the immutable patch."
  },
  "applicability": {
    "status": "confirmed",
    "rationale": "The failing assertion is in the changed workflow's source-models job and runs before downstream source-and-go."
  },
  "statusQuoRisk": {
    "rating": "moderate",
    "rationale": "Without a corrected truncation patch, more than eight valid locations remain UNKNOWN rather than safely truncated."
  },
  "autoMergeExclusions": [
    "other"
  ],
  "affectedRuntimeRoots": [
    "GitHub Actions source-models gate",
    "CI failure diagnostic projector"
  ],
  "importantCallers": [
    "chengwang-subscription-refresh.yml source-models job",
    "test_go_failure.py model inventory"
  ],
  "riskDrivers": [
    "Renamed model test top without synchronized workflow digest"
  ],
  "protectiveFactors": [
    "The bounded truncation algorithm keeps only eight locations",
    "Full bounded stderr scan continues after overflow",
    "Later malformed or foreign positions still collapse to UNKNOWN",
    "Reader whole-object reprojection and final gates remain strict"
  ],
  "materialBoundaries": [
    {
      "id": "source-model-identity",
      "invariant": "The workflow's pinned 61-name digest must equal the exact AST inventory of the four source-model files.",
      "runtimeRoot": "chengwang-subscription-refresh.yml source-models job",
      "counterexample": "A model method is renamed while the workflow retains the prior digest.",
      "legitimateControl": "The workflow recomputes the digest, but the candidate does not update it; the boundary is contradicted.",
      "result": "contradicted"
    },
    {
      "id": "bounded-truncation",
      "invariant": "Only fully validated stderr with more than eight unique declared locations may emit a stable top-eight TRUNCATED report.",
      "runtimeRoot": "check_go_failure.py project_build_locations",
      "counterexample": "The ninth location causes an early return or a later foreign/malformed location is ignored.",
      "legitimateControl": "A maximum-eight sorted list is maintained while the complete bounded stderr is scanned; later invalid data returns UNKNOWN with no locations.",
      "result": "supported"
    },
    {
      "id": "privacy-and-acceptance",
      "invariant": "Truncation must not export messages/private inputs or relax acceptance.",
      "runtimeRoot": "check_go_failure.py verify_report and workflow",
      "counterexample": "A truncated report includes raw text or turns failed Go/event exits green.",
      "legitimateControl": "Only declared path/line/column entries are emitted; reader reprojects from private inputs; workflow final and fresh gates are unchanged.",
      "result": "supported"
    }
  ],
  "validation": [
    {
      "name": "Immutable patch and afterimage hashes",
      "status": "passed",
      "protects": "Binds review to the 19431-byte patch and three frozen afterimages."
    },
    {
      "name": "Independent static source-model inventory",
      "status": "failed",
      "protects": "Shows the workflow expects 1093918b while the candidate files compute 49798156."
    },
    {
      "name": "Supplied 61-model and source-check evidence",
      "status": "passed",
      "protects": "Covers model behavior and source closure but not the stale inline workflow digest."
    },
    {
      "name": "Go and Linux CI",
      "status": "skipped",
      "protects": "Intentionally outside this source-only review."
    }
  ],
  "unknowns": [],
  "evidencePlan": []
}
```
