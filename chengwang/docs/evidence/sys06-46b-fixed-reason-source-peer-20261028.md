# Independent fixed build-location reason source review

Verdict: **SOURCE_ACCEPT**

- Base: `46b214690dc4680e5de2e812ddbf54fcf406a584`
- Exact patch: 17,785 bytes
- Patch SHA-256: `b657345e3007af9b0e506c12d0939ac9e2e152f90c628e4b9f4fa47050f0da82`
- Frozen after-set SHA-256: `1952c7a10a3e502e03f7ff0b068bdaa4d9fef06347b7dd4d06558aee50aacd99`
- Findings: none

The three afterimages match the frozen manifest. The patch adds exactly eleven fixed reasons, three fixed stderr classes, and the closed position-count buckets `0` through `8` plus `OVER8`. The existing location parser's prefixes, syntax, source pins, line/column ranges, control and UTF-8 checks, input/line budgets, maximum eight locations, and fail-closed behavior are not widened.

All 46 pinned `subscriptionctl` tops must still be `NOT_STARTED`. Producer and reader use the same runner-private events, stderr, repository, contract, Go exit, and event-check exit; reader mode reprojects the whole report and requires exact equality. New fields cannot carry compiler text, arbitrary paths, URLs, dynamic test names, hashes, or secrets. Raw stderr and events remain outside artifacts. Workflow success, freshness, and acceptance gates are unchanged.

Static review independently confirms 61 unique model tops and names digest `1093918bbaafd00a40b06a4d7e9856126a89a18c53cf7ff2d9a52864170b48bd`. The supplied exact source checker and 61-model evidence are consistent.

Boundary: source-only review. I did not run Go, gofmt, Linux CI, browser, service, network, or production actions, and did not rerun the 61 models. The actual reason for the prior `UNKNOWN` result remains unproven until a new exact-head run.

```json
{
  "schemaVersion": 1,
  "patch": {
    "repository": "D:/CodexData/workspace/mihomo-46b-build-location-reason-20261028-implementation56h-v1/repo",
    "sourceType": "patch_file",
    "base": "46b214690dc4680e5de2e812ddbf54fcf406a584",
    "head": "working-tree-afterimage-1952c7a10a3e502e03f7ff0b068bdaa4d9fef06347b7dd4d06558aee50aacd99",
    "changedFiles": [
      ".github/workflows/chengwang-subscription-refresh.yml",
      "chengwang/deploy/subscription-refresh/check_go_failure.py",
      "chengwang/deploy/subscription-refresh/test_go_failure.py"
    ],
    "sha256": "b657345e3007af9b0e506c12d0939ac9e2e152f90c628e4b9f4fa47050f0da82"
  },
  "recommendation": "merge",
  "workflowLabel": "human_review_required",
  "impact": {
    "rating": "moderate",
    "rationale": "The patch changes privacy-sensitive CI failure metadata but not product runtime source or acceptance behavior."
  },
  "regressionLikelihood": {
    "rating": "low",
    "rationale": "It adds only fixed closed enums and buckets around the unchanged fail-closed location parser, with whole-report private-input reprojection."
  },
  "regressionProtection": {
    "rating": "partial",
    "rationale": "The supplied frozen-candidate 61-model run and exact source checker passed, and static inventory/pins were independently verified; Go and Linux CI were intentionally not run.",
    "exactHeadChecksPassed": false
  },
  "recoverability": {
    "rating": "easy",
    "rationale": "The three-file CI-only patch is stateless and directly revertible."
  },
  "confidence": {
    "rating": "high",
    "rationale": "Exact patch identity, all three afterimages, closed enums, parser delta, eligibility, reader equality, workflow uploads/gates, and source pins were inspected."
  },
  "applicability": {
    "status": "confirmed",
    "rationale": "The workflow invokes this projector and reader on failed Go or event checks."
  },
  "statusQuoRisk": {
    "rating": "moderate",
    "rationale": "Without the patch, an UNKNOWN location result does not reveal which fixed fail-closed parser gate was reached."
  },
  "autoMergeExclusions": [
    "other"
  ],
  "affectedRuntimeRoots": [
    "GitHub Actions source-and-go failure diagnostic path"
  ],
  "importantCallers": [
    "check_go_failure.py producer mode",
    "check_go_failure.py reader mode",
    "chengwang-subscription-refresh.yml"
  ],
  "riskDrivers": [
    "Fixed metadata is derived from runner-private stderr",
    "No independent Go/Linux execution"
  ],
  "protectiveFactors": [
    "Location parser accept surface is unchanged",
    "Eleven reasons, three stderr classes, and ten count buckets are closed enums",
    "Reader recomputes the entire report from identical private inputs",
    "Raw stderr and events remain unuploaded",
    "Success and fresh gates are unchanged"
  ],
  "materialBoundaries": [
    {
      "id": "fixed-reason-privacy",
      "invariant": "Only fixed reason, stderr class, bounded count bucket, and previously allowed location fields may leave private stderr.",
      "runtimeRoot": "check_go_failure.py project_build_locations",
      "counterexample": "Private compiler text, path, URL, secret, or arbitrary count is copied into the report.",
      "legitimateControl": "All new fields are selected from closed constants; messages are never copied; locations remain exact declared path/line/optional-column and max eight.",
      "result": "supported"
    },
    {
      "id": "parser-nonexpansion",
      "invariant": "Adding reasons must not widen any accepted position syntax or source path.",
      "runtimeRoot": "check_go_failure.py location parser",
      "counterexample": "A foreign, absolute, traversal, URL, malformed, control, invalid UTF-8, out-of-range, or overflow position becomes observed.",
      "legitimateControl": "Patterns, prefixes, range checks, budgets, control checks, and UNKNOWN returns are unchanged except for fixed reason/count annotations.",
      "result": "supported"
    },
    {
      "id": "eligibility-and-integrity",
      "invariant": "Projection remains eligible only when all 46 pinned subscriptionctl tops are NOT_STARTED and report edits cannot survive reading.",
      "runtimeRoot": "check_go_failure.py project and verify_report",
      "counterexample": "A started target top receives a location or coordinated reason/class/count tampering passes shape checks.",
      "legitimateControl": "The original all-NOT_STARTED predicate is unchanged; reader uses the same events, stderr, repo, contract, and two exits and requires whole-object equality.",
      "result": "supported"
    },
    {
      "id": "acceptance-gates",
      "invariant": "Reason diagnostics must not turn a failed run green or relax fresh acceptance.",
      "runtimeRoot": "chengwang-subscription-refresh.yml",
      "counterexample": "A valid diagnostic report bypasses nonzero Go/event exits or lets fresh run.",
      "legitimateControl": "Workflow diff changes only failure checker/model hashes; final zero-exit, empty-stderr, accepted evidence, and fresh dependency gates are byte-unchanged.",
      "result": "supported"
    }
  ],
  "validation": [
    {
      "name": "Immutable patch and afterimage hashes",
      "status": "passed",
      "protects": "Binds review to the 17785-byte patch and three frozen afterimages."
    },
    {
      "name": "Static source inventory and contract cardinality",
      "status": "passed",
      "protects": "Confirms 61 unique model tops with pinned digest and 46 unique subscriptionctl tops."
    },
    {
      "name": "Supplied 61-model and exact source checker evidence",
      "status": "passed",
      "protects": "Reports all 61 models passing and closure 825/20/486/481/24."
    },
    {
      "name": "Go, gofmt, and exact-head Linux CI",
      "status": "skipped",
      "protects": "Would observe the actual fixed reason; intentionally outside this source-only review."
    }
  ],
  "unknowns": [
    {
      "summary": "The actual 46b UNKNOWN reason remains unknown until a new exact-head Linux run.",
      "decisionCritical": false
    }
  ],
  "evidencePlan": []
}
```
