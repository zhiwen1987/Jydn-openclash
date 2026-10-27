# Independent clock plus build-diagnostic combo source review

Verdict: **SOURCE_ACCEPT**

Exact patch: 32,576 bytes; SHA-256 `77678b8c99dd57f31c7a53ad2fcab433ea060fab16812c0ae4ca6506c5790722`; base `041e5a207169b06219888119acd876c95ac79372`.

The combo is exactly the seven-path union of the two accepted leaves. All six non-workflow files are byte-identical to their leaf afterimages. The workflow is byte-identical to the build-diagnostic leaf after substituting exactly one each of `CONTRACT_SHA256`, `MODULE_SHA256`, and `CHANGED_GO_SHA256` from the clock leaf.

The source checker reports 825 module paths, 20 fixtures, 486 package tops, 481 required tops, and 24 changed Go sources. Static inventory independently confirms 61 unique model names and digest `1093918bbaafd00a40b06a4d7e9856126a89a18c53cf7ff2d9a52864170b48bd`. Root's frozen-candidate 61-model run passed with exit 0 and no skips.

Producer and reader retain the same private events, stderr, repository, contract, and two exits; reader requires whole-report equality. Raw stderr/events remain outside uploads. The report is non-accepting, Go/event success gates and fresh dependency remain strict, and product time validation is unchanged.

Boundary: source-only peer. I did not run Go, gofmt, browser, Linux CI, service, or production actions, and did not repeat the 61 models.

```json
{
  "schemaVersion": 1,
  "patch": {
    "repository": "D:/CodexData/workspace/mihomo-041-clock-build-combo-root-eav49an1/repo",
    "sourceType": "patch_file",
    "base": "041e5a207169b06219888119acd876c95ac79372",
    "head": "working-tree-afterimage-clock-build-combo",
    "changedFiles": [
      ".github/workflows/chengwang-subscription-refresh.yml",
      "chengwang/deploy/subscription-refresh/check_go_failure.py",
      "chengwang/deploy/subscription-refresh/check_source_contract.py",
      "chengwang/deploy/subscription-refresh/source_contract.json",
      "chengwang/deploy/subscription-refresh/test_go_failure.py",
      "chengwang/deploy/subscription-refresh/test_source_contract.py",
      "chengwang/internal/subscription/refresh_test.go"
    ],
    "sha256": "77678b8c99dd57f31c7a53ad2fcab433ea060fab16812c0ae4ca6506c5790722"
  },
  "recommendation": "merge",
  "workflowLabel": "human_review_required",
  "impact": {
    "rating": "moderate",
    "rationale": "The combination changes a test fixture and privacy-sensitive CI failure diagnostics, but not product runtime source."
  },
  "regressionLikelihood": {
    "rating": "low",
    "rationale": "Six non-workflow files are byte-identical to accepted leaves; the workflow is an exact build leaf with only the three clock-leaf source pins substituted."
  },
  "regressionProtection": {
    "rating": "partial",
    "rationale": "Exact source closure, static 61-name inventory, and root's frozen-candidate 61-model run passed; Go/gofmt were not run by this peer.",
    "exactHeadChecksPassed": false
  },
  "recoverability": {
    "rating": "easy",
    "rationale": "The seven-file CI/test-only patch has no migration or persistent state and is directly revertible."
  },
  "confidence": {
    "rating": "high",
    "rationale": "The union, exact leaf bytes, workflow composition, pins, diagnostic inputs/uploads/gates, and unchanged product time validator were independently inspected."
  },
  "applicability": {
    "status": "confirmed",
    "rationale": "The workflow uses the merged diagnostic reader and source pins, and the existing test top uses the merged clock fixture."
  },
  "statusQuoRisk": {
    "rating": "moderate",
    "rationale": "Without the combination, the flaky future-clock test remains and failed pre-test compilation lacks a bounded location diagnostic."
  },
  "autoMergeExclusions": [
    "other"
  ],
  "affectedRuntimeRoots": [
    "GitHub Actions source-and-go diagnostic path",
    "TestRefreshV3CandidatePreservesAcceptedVersion fixture"
  ],
  "importantCallers": [
    "chengwang-subscription-refresh.yml producer and reader invocations",
    "subscription.Store.Import test call",
    "subscription.Store.RecordControlResult test call"
  ],
  "riskDrivers": [
    "Private stderr is parsed",
    "Independent Go/Linux execution was not part of this peer review"
  ],
  "protectiveFactors": [
    "Six files are exact accepted leaf afterimages",
    "Shared workflow is an exact deterministic composition",
    "Raw private inputs remain unuploaded",
    "Product time validation and final gates remain strict"
  ],
  "materialBoundaries": [
    {
      "id": "leaf-composition",
      "invariant": "The combo must be only the union of two accepted leaves with a deterministic shared workflow merge.",
      "runtimeRoot": "seven changed files",
      "counterexample": "A non-workflow file drifts or workflow contains a third semantic change.",
      "legitimateControl": "Six byte comparisons pass; workflow equals the complete build leaf after exactly one substitution each for CONTRACT, MODULE, and CHANGED_GO pins.",
      "result": "supported"
    },
    {
      "id": "private-diagnostic",
      "invariant": "Only bounded declared location metadata may leave runner-private stderr and events.",
      "runtimeRoot": "check_go_failure.py and workflow uploads",
      "counterexample": "Raw stderr, events, foreign paths, URLs, or message text enter the artifact.",
      "legitimateControl": "Exact source allowlist and UNKNOWN fallback are preserved; producer and reader use the same private inputs and workflow uploads neither raw file.",
      "result": "supported"
    },
    {
      "id": "acceptance-gates",
      "invariant": "Diagnostics and the fixture must not relax product validation or CI success/freshness.",
      "runtimeRoot": "control.go and workflow final gates",
      "counterexample": "A report or clock fixture turns a failed run green or bypasses CompletedAt validation.",
      "legitimateControl": "control.go is unchanged; report remains non-accepting; workflow still requires zero Go/event exits, empty stderr, and fresh depends on source-and-go.",
      "result": "supported"
    }
  ],
  "validation": [
    {
      "name": "Immutable combo patch and manifest hashes",
      "status": "passed",
      "protects": "Binds the review to the 32576-byte patch and seven afterimages."
    },
    {
      "name": "Exact leaf composition",
      "status": "passed",
      "protects": "Confirms six exact afterimages and the single deterministic workflow merge."
    },
    {
      "name": "Static model inventory and source closure",
      "status": "passed",
      "protects": "Confirms 61 unique model names/digest and source closure 825/20/486/481/24."
    },
    {
      "name": "Root frozen-candidate 61-model CPU run",
      "status": "passed",
      "protects": "Confirms all 61 Python source models passed at the unchanged seven-path afterimage with no skips."
    },
    {
      "name": "Go, gofmt, and Linux CI",
      "status": "skipped",
      "protects": "Would validate product compilation and platform execution; intentionally outside this source-only peer review."
    }
  ],
  "unknowns": [
    {
      "summary": "Exact-head Go and Linux CI execution were not performed in this source-only review.",
      "decisionCritical": false
    }
  ],
  "evidencePlan": []
}
```
