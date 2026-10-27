# Independent fail-closed workflow source review

Verdict: **SOURCE_ACCEPT**

- Base: `abd20d2ff14c4fe5282e8814daa69fcdffa4a2f8`
- Exact patch: 22,905 bytes
- Patch SHA-256: `c701af826ae20ae447245d5401515eb068f4793ace9b72b6f612d5ebef5cba52`
- Findings: none

The three afterimages match the frozen manifest. The producer accepted-evidence gate now uses independent Bash test commands for format exit, both formatting outputs, Go exit, event-check exit, diagnostic-reader exit, private stderr, and every accepted public member. Its upload remains exactly nine declared public members: seven required nonempty reports/exit files plus two required present-and-empty formatting files.

The fresh gate independently rejects every missing public member, nonempty formatting output, and nonzero format/Go/event exit before any comparison or report reader. The source-and-go failure diagnostic upload remains present. Neither `go-events.private.jsonl` nor `go.stderr` is uploaded.

The source checker extracts each uniquely marked gate and requires exact equality with a fixed command tuple. Both extracted scripts are checked to contain no `&&`. The Bash regression executes only the accepted fixed gate prefixed with `set -euo pipefail`, uses `--noprofile --norc`, and removes `BASH_ENV`, `ENV`, `SHELLOPTS`, and `BASHOPTS`. It verifies the valid case, nonzero Go/event cases, nonempty formatting outputs, missing public members, and rejects restoration of the old AND lists.

Independent AST comparison confirms all prior 62 model names plus exactly `test_source_contract.py::test_workflow_fixed_gate_is_bash_fail_closed_and_rejects_and_lists`; the resulting 63-name digest `381d6fd992de5fffe1ee56bc52449d2be561078b2b05dd5050dc6607926459dd` matches the workflow. Checker/model pins match their afterimages.

The supplied 63-model CPU run, exact source checker, source-model log replay, and isolated Git Bash regression passed. This peer did not repeat them.

Boundary: source-only review. No Go, gofmt, network, Linux workflow, browser, service, or production action was run. Go success and the underlying Go failure remain unproven pending a new exact-head Linux run.

```json
{
  "schemaVersion": 1,
  "patch": {
    "repository": "D:/CodexData/workspace/mihomo-abd-workflow-failclosed-20261028-implementation56h-v1/repo",
    "sourceType": "patch_file",
    "base": "abd20d2ff14c4fe5282e8814daa69fcdffa4a2f8",
    "head": "working-tree-afterimage-workflow-failclosed",
    "changedFiles": [
      ".github/workflows/chengwang-subscription-refresh.yml",
      "chengwang/deploy/subscription-refresh/check_source_contract.py",
      "chengwang/deploy/subscription-refresh/test_source_contract.py"
    ],
    "sha256": "c701af826ae20ae447245d5401515eb068f4793ace9b72b6f612d5ebef5cba52"
  },
  "recommendation": "merge",
  "workflowLabel": "human_review_required",
  "impact": {
    "rating": "moderate",
    "rationale": "The patch controls CI acceptance and artifact publication; a regression could falsely accept a failed lane or publish an incomplete evidence set."
  },
  "regressionLikelihood": {
    "rating": "low",
    "rationale": "Producer and fresh gates are exact fixed command sequences with independent tests, source-model identity is recomputed from all four ASTs, and upload/privacy surfaces remain closed."
  },
  "regressionProtection": {
    "rating": "partial",
    "rationale": "The supplied 63-model, exact source checker, log replay, and isolated Git Bash gate regression passed; Go and exact-head Linux workflow execution were intentionally not run.",
    "exactHeadChecksPassed": false
  },
  "recoverability": {
    "rating": "easy",
    "rationale": "The three-file workflow/checker/model patch is stateless and directly revertible."
  },
  "confidence": {
    "rating": "high",
    "rationale": "Exact patch identity, three afterimages, workflow gates, nine-member upload set, source checker grammar, regression harness, model set, and privacy/failure uploads were inspected."
  },
  "applicability": {
    "status": "confirmed",
    "rationale": "The changed workflow is the active closed lane and both producer and fresh jobs execute the new gates."
  },
  "statusQuoRisk": {
    "rating": "high",
    "rationale": "The old Bash AND lists can suppress errexit on the first failed test and permit later commands to continue."
  },
  "autoMergeExclusions": [
    "other"
  ],
  "affectedRuntimeRoots": [
    "GitHub Actions source-and-go accepted-evidence gate",
    "GitHub Actions fresh readback gate"
  ],
  "importantCallers": [
    "check_source_contract.py verify_workflow_surface",
    "source-models workflow job",
    "source-and-go workflow job",
    "fresh workflow job"
  ],
  "riskDrivers": [
    "CI acceptance semantics depend on Bash errexit behavior",
    "Exact-head Linux workflow not yet executed"
  ],
  "protectiveFactors": [
    "Every gate check is an independent command",
    "Accepted upload has exactly nine public members",
    "Required reports and exit files must be nonempty",
    "Empty formatting files and empty private stderr are independently enforced",
    "Raw Go events and stderr remain absent from uploads",
    "Failure diagnostic upload remains available"
  ],
  "materialBoundaries": [
    {
      "id": "producer-fail-closed",
      "invariant": "Every format, Go, event, diagnostic-reader, private-stderr, and accepted-member condition must independently fail the producer.",
      "runtimeRoot": "P207A_ACCEPTED_GATE",
      "counterexample": "A failed first term in a Bash AND list is exempt from errexit and later commands continue.",
      "legitimateControl": "The fixed gate contains no AND list and binds each condition to one exact independent test command before upload.",
      "result": "supported"
    },
    {
      "id": "fresh-fail-closed",
      "invariant": "Fresh must reject each missing/nonzero/format condition before comparing or reading reports.",
      "runtimeRoot": "P207A_FRESH_GATE",
      "counterexample": "A missing report or failed first AND term reaches report validation.",
      "legitimateControl": "The fresh fixed gate has an exact independent command list and is required to end before the first cmp/report reader.",
      "result": "supported"
    },
    {
      "id": "artifact-privacy",
      "invariant": "Accepted upload contains only nine declared public members and failure diagnostics retain bounded reports without raw events or stderr.",
      "runtimeRoot": "workflow upload-artifact steps",
      "counterexample": "Private go-events.private.jsonl or go.stderr enters an upload path.",
      "legitimateControl": "The exact accepted and failure upload lists omit both raw inputs; accepted gate requires all nine public members and failure upload remains conditional on failure.",
      "result": "supported"
    },
    {
      "id": "source-model-binding",
      "invariant": "Workflow count/digest/log replay must bind the exact four source-model AST inventories.",
      "runtimeRoot": "source_model_names and source-models job",
      "counterexample": "A model method is added or renamed without updating workflow identity.",
      "legitimateControl": "The source checker derives names from all four ASTs; independent set comparison confirms all prior 62 names plus one added and digest 381d6fd9.",
      "result": "supported"
    },
    {
      "id": "bash-regression-harness",
      "invariant": "The regression harness must execute only the extracted fixed gate under a clean Bash option environment.",
      "runtimeRoot": "test_workflow_fixed_gate_is_bash_fail_closed_and_rejects_and_lists",
      "counterexample": "Profiles, BASH_ENV, ENV, SHELLOPTS, BASHOPTS, or arbitrary workflow text alter the test.",
      "legitimateControl": "The checker returns only the exact allowlisted gate prefixed by set -euo pipefail; the test uses --noprofile --norc and removes all four environment variables.",
      "result": "supported"
    }
  ],
  "validation": [
    {
      "name": "Immutable patch and afterimage hashes",
      "status": "passed",
      "protects": "Binds review to the 22905-byte patch and three frozen afterimages."
    },
    {
      "name": "Independent AST model set comparison",
      "status": "passed",
      "protects": "Confirms prior 62 names plus one exact added name and digest 381d6fd9."
    },
    {
      "name": "Supplied 63-model, source checker, log replay, and Git Bash regression",
      "status": "passed",
      "protects": "Exercises the fixed gate and source bindings without claiming Go/Linux workflow execution."
    },
    {
      "name": "Go and exact-head Linux workflow",
      "status": "skipped",
      "protects": "Intentionally outside this source-only review."
    }
  ],
  "unknowns": [
    {
      "summary": "A new exact-head Linux workflow has not yet proved Go success or the underlying Go failure cause.",
      "decisionCritical": false
    }
  ],
  "evidencePlan": []
}
```
