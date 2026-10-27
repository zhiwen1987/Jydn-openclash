# Independent clock-fixture source review

Verdict: **SOURCE_ACCEPT**

Exact patch: 4,693 bytes; SHA-256 `dad8820b9b353fd36aeabb07dd133a558100e8591bc9ed0ece6d4342c026f328`; base `041e5a207169b06219888119acd876c95ac79372`.

The three afterimages match the frozen manifest. The only semantic change sets the test-local domain clock to the same immutable `now` used as `ControlCommand.PreparedAt`. Import candidate/audit/receipt timestamps therefore equal PreparedAt, while the product `CompletedAt.Before(PreparedAt)` rejection remains unchanged. The store is local to this top-level test, with no concurrent or cross-test clock reach. Contract and workflow pins match the changed test, module aggregate, and changed-Go aggregate; path and top counts remain 825/24/486/481.

Boundary: source-only review. No Go, gofmt, browser, Linux CI, service, or production action was run.

```json
{
  "schemaVersion": 1,
  "patch": {
    "repository": "D:/CodexData/workspace/mihomo-041-clock-fixture-root-8hc14iny/repo",
    "sourceType": "patch_file",
    "base": "041e5a207169b06219888119acd876c95ac79372",
    "head": "working-tree-afterimage-clock-fixture",
    "changedFiles": [
      ".github/workflows/chengwang-subscription-refresh.yml",
      "chengwang/deploy/subscription-refresh/source_contract.json",
      "chengwang/internal/subscription/refresh_test.go"
    ],
    "sha256": "dad8820b9b353fd36aeabb07dd133a558100e8591bc9ed0ece6d4342c026f328"
  },
  "recommendation": "merge",
  "workflowLabel": "human_review_required",
  "impact": {
    "rating": "low",
    "rationale": "Only one existing test fixture clock and its source pins change; product code and runtime behavior remain unchanged."
  },
  "regressionLikelihood": {
    "rating": "low",
    "rationale": "The injected per-test store clock equals PreparedAt, preserves the strict product time gate, and has no cross-test or concurrent reach."
  },
  "regressionProtection": {
    "rating": "partial",
    "rationale": "Exact source closure passed, but this peer intentionally did not run Go, gofmt, or model tests.",
    "exactHeadChecksPassed": false
  },
  "recoverability": {
    "rating": "easy",
    "rationale": "The isolated three-file patch is stateless and directly revertible."
  },
  "confidence": {
    "rating": "high",
    "rationale": "All three afterimages, the one semantic line, the receipt time chain, and all changed pins were inspected."
  },
  "applicability": {
    "status": "confirmed",
    "rationale": "The failing declared top directly executes the changed test fixture."
  },
  "statusQuoRisk": {
    "rating": "moderate",
    "rationale": "Without the fixture clock, the test conditionally rejects a receipt created before its synthetic future PreparedAt."
  },
  "autoMergeExclusions": [
    "other"
  ],
  "affectedRuntimeRoots": [
    "TestRefreshV3CandidatePreservesAcceptedVersion fixture only"
  ],
  "importantCallers": [
    "subscription.Store.Import test call",
    "subscription.Store.RecordControlResult test call"
  ],
  "riskDrivers": [
    "No independent Go execution"
  ],
  "protectiveFactors": [
    "No product source changes",
    "Strict CompletedAt validation is unchanged",
    "Source checker closure passed"
  ],
  "materialBoundaries": [
    {
      "id": "time-contract",
      "invariant": "The fixture must make mutation receipt completion no earlier than command preparation without weakening product validation.",
      "runtimeRoot": "chengwang/internal/subscription/refresh_test.go",
      "counterexample": "Default wall clock returns a receipt before the synthetic PreparedAt two minutes in the future.",
      "legitimateControl": "The test-local domain clock returns the same now used for PreparedAt; control.go Before validation is unchanged.",
      "result": "supported"
    },
    {
      "id": "source-pins",
      "invariant": "The one changed Go afterimage must be bound by exact contract and workflow pins.",
      "runtimeRoot": "source_contract.json and workflow env",
      "counterexample": "The test changes while module, changed-Go, or contract hashes remain stale.",
      "legitimateControl": "The changed file hash, module aggregate, changed-Go aggregate, contract hash, and three workflow pins exactly match.",
      "result": "supported"
    }
  ],
  "validation": [
    {
      "name": "Immutable patch and manifest hashes",
      "status": "passed",
      "protects": "Binds the review to patch dad8820b and the frozen three afterimages."
    },
    {
      "name": "Exact source checker evidence",
      "status": "passed",
      "protects": "Reports 825 module paths, 24 changed Go sources, 486 package tops, and 481 required tops."
    },
    {
      "name": "Go and gofmt",
      "status": "skipped",
      "protects": "Would validate execution; intentionally outside this peer review."
    }
  ],
  "unknowns": [
    {
      "summary": "Exact-head Go execution was not performed by this peer.",
      "decisionCritical": false
    }
  ],
  "evidencePlan": []
}
```
