# Independent receipt-helper plus truncated-diagnostic combo source review

Verdict: **SOURCE_ACCEPT**

- Base: `0766c7f7475b5e31633d6093e952d0d360872d4d`
- Exact patch: 25,926 bytes
- Patch SHA-256: `97c412228dead761fdbcdef00480a03b02b6bd0ee23e1c1642d645b80b824bff`
- Findings: none

The five afterimages match the frozen manifest. The test-only Go helper now declares its fourth result as the same `Receipt` type returned by `e.create`; all four callers either use `Receipt.SourceID` or discard the value. No product Go source changes.

The workflow model inventory is now exact: all original 61 names remain and one separately named positive truncation test is added. The resulting 62-name digest is `a90810c3944e4dc681825364ab1595c9e90c172a1d0e987f32795ca6113493c6`, exactly matching the workflow. The legacy test name truthfully checks nine valid positions combined with over-budget stderr, which must remain UNKNOWN.

The diagnostic projector retains at most eight sorted locations and continues scanning the complete bounded stderr. A ninth or later fully valid unique location sets overflow without growing location storage. Any later foreign, malformed, out-of-range, oversized-line, control-byte, invalid-UTF-8, or total-budget failure returns UNKNOWN with an empty list. Only an entirely valid stream with more than eight unique declared positions yields TRUNCATED / LOCATION_COUNT_OVERFLOW / OVER8 / true and exactly eight stable locations.

The updated source declaration hash, contract Go hash, module and changed-Go aggregates, and workflow CONTRACT/MODULE/CHANGED_GO/FAILURE_CHECKER/FAILURE_MODEL pins all match. Source closure remains 825/20/486/481/24. Producer and reader retain identical private events, stderr, repository, contract and two exits with whole-object equality. Raw inputs remain unuploaded, and acceptance/final/fresh gates are unchanged.

Root's frozen-candidate 62-model run completed PASS in 38.221 seconds with exit 0 and no skips; the exact workflow AST inventory and source-model log replay also passed. This peer did not repeat it.

Boundary: source-only review. No Go, gofmt, Linux CI, browser, service, network, or production action was run by this peer.

```json
{
  "schemaVersion": 1,
  "patch": {
    "repository": "D:/CodexData/workspace/mihomo-0766-receipt-truncated-combo-root-sto36lf5/repo",
    "sourceType": "patch_file",
    "base": "0766c7f7475b5e31633d6093e952d0d360872d4d",
    "head": "working-tree-afterimage-receipt-truncated-combo",
    "changedFiles": [
      ".github/workflows/chengwang-subscription-refresh.yml",
      "chengwang/deploy/subscription-refresh/check_go_failure.py",
      "chengwang/deploy/subscription-refresh/source_contract.json",
      "chengwang/deploy/subscription-refresh/test_go_failure.py",
      "chengwang/internal/subscriptionctl/service_linux_test.go"
    ],
    "sha256": "97c412228dead761fdbcdef00480a03b02b6bd0ee23e1c1642d645b80b824bff"
  },
  "recommendation": "merge",
  "workflowLabel": "human_review_required",
  "impact": {
    "rating": "moderate",
    "rationale": "The combo changes a test-only Go helper and privacy-sensitive CI diagnostics, with no product Go source or persistent state change."
  },
  "regressionLikelihood": {
    "rating": "low",
    "rationale": "The type contract is corrected exactly, the bounded truncation algorithm scans all bounded input with constant location storage, and all cross-file pins are synchronized."
  },
  "regressionProtection": {
    "rating": "partial",
    "rationale": "Exact source closure, independent static model inventory, and root's frozen-candidate 62-model run plus exact workflow-log replay passed; Go/Linux CI were intentionally not run.",
    "exactHeadChecksPassed": false
  },
  "recoverability": {
    "rating": "easy",
    "rationale": "The five-file test/CI-only patch has no migration or state change and is directly revertible."
  },
  "confidence": {
    "rating": "high",
    "rationale": "Patch identity, five afterimages, old/new model sets, helper callers, parser state machine, source declarations, contract aggregates, workflow pins/uploads/gates were inspected."
  },
  "applicability": {
    "status": "confirmed",
    "rationale": "The helper participates in declared Go tests and the workflow invokes the changed diagnostic producer and reader."
  },
  "statusQuoRisk": {
    "rating": "high",
    "rationale": "The base has a deterministic test compile type mismatch and cannot safely publish more than eight valid locations."
  },
  "autoMergeExclusions": [
    "other"
  ],
  "affectedRuntimeRoots": [
    "subscriptionctl Linux test package compilation",
    "GitHub Actions failure diagnostic path"
  ],
  "importantCallers": [
    "ctlTestRefreshWorker callers",
    "check_go_failure.py producer and reader",
    "chengwang-subscription-refresh.yml"
  ],
  "riskDrivers": [
    "Private stderr is parsed",
    "Go/Linux execution not performed by this peer"
  ],
  "protectiveFactors": [
    "No product Go source changes",
    "All prior 61 model names preserved and one precise model added",
    "Only eight sorted locations are retained",
    "Full bounded stderr is scanned before truncation",
    "Later invalid data collapses to UNKNOWN empty",
    "Whole-object private-input reprojection and final gates remain strict"
  ],
  "materialBoundaries": [
    {
      "id": "receipt-helper-type",
      "invariant": "ctlTestRefreshWorker fourth result must match e.create and caller SourceID usage.",
      "runtimeRoot": "service_linux_test.go",
      "counterexample": "The helper declares SourceView while returning Receipt and callers access SourceID.",
      "legitimateControl": "The declaration now uses Receipt; all four callers either access Receipt.SourceID or discard the result.",
      "result": "supported"
    },
    {
      "id": "model-inventory",
      "invariant": "The workflow model count and digest must match the exact source set without dropping prior names.",
      "runtimeRoot": "source-models workflow job",
      "counterexample": "A renamed test changes the digest while the old workflow pin remains.",
      "legitimateControl": "Independent set comparison proves all 61 prior names remain, one new positive truncation test is added, and count 62/digest a90810c3 match the workflow.",
      "result": "supported"
    },
    {
      "id": "bounded-full-scan",
      "invariant": "At most eight locations are retained while every bounded stderr line is validated; later invalid data must erase locations.",
      "runtimeRoot": "check_go_failure.py project_build_locations",
      "counterexample": "The ninth valid location stops scanning, allowing a later foreign or malformed location to pass.",
      "legitimateControl": "A maximum-eight sorted list and overflow flag are maintained without early return; any later syntax, range, foreign, line, control, UTF-8, or input failure returns UNKNOWN with an empty list.",
      "result": "supported"
    },
    {
      "id": "privacy-acceptance",
      "invariant": "TRUNCATED remains non-accepting and exports no compiler text or raw private input.",
      "runtimeRoot": "check_go_failure.py verify_report and workflow",
      "counterexample": "A truncated report leaks message text or bypasses Go/event/fresh gates.",
      "legitimateControl": "Only pinned path/line/column locations and fixed fields are emitted; reader requires whole-object reprojection; workflow uploads no raw input and final/fresh gates are unchanged.",
      "result": "supported"
    }
  ],
  "validation": [
    {
      "name": "Immutable patch and afterimage hashes",
      "status": "passed",
      "protects": "Binds review to the 25926-byte patch and five frozen afterimages."
    },
    {
      "name": "Exact source checker evidence",
      "status": "passed",
      "protects": "Confirms source closure 825/20/486/481/24 and synchronized Go/module/map pins."
    },
    {
      "name": "Independent AST model set comparison",
      "status": "passed",
      "protects": "Confirms original 61 names preserved, one added, and exact 62-name digest."
    },
    {
      "name": "Root frozen-candidate 62-model CPU and workflow-log replay",
      "status": "passed",
      "protects": "Confirms 62 models passed with no skips and the exact source-model log validates against the workflow inventory."
    },
    {
      "name": "Go and Linux CI",
      "status": "skipped",
      "protects": "Intentionally outside this source-only peer review."
    }
  ],
  "unknowns": [
    {
      "summary": "Go and Linux CI execution were not performed by this source-only peer.",
      "decisionCritical": false
    }
  ],
  "evidencePlan": []
}
```
