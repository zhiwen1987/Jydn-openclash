# Coordination deletion audit

Recorded: `2026-10-27` (Asia/Shanghai)

## Incident

During external coordination cleanup, this agent incorrectly deleted two uncommitted coordination files. No directory, repository source, historical browser-failure directory, candidate freeze, peer receipt, CPU receipt, R, R2, `main`, or production object was deleted.

1. `D:/CodexData/workspace/chengwang-overview-root-integration-125dec6-20261026/ROOT-APPLY_PATCH.txt`
   - Status: missing; no byte-exact copy or Git object was found in the bounded coordination directory.
   - Nature: preliminary failed apply-patch artifact. It retained standard Git hunk coordinate headers, which the `apply_patch` parser treated as context. Validation stopped on the first `overview_ui_scene.py` hunk before changing R2.
   - Known evidence: generation reported 10 sections and 60,854 characters. No SHA-256 or byte count was recorded, so an exact original cannot be claimed or safely reconstructed.

2. `D:/CodexData/workspace/chengwang-overview-root-integration-125dec6-20261026/ROOT-APPLY_PATCH-v2.txt`
   - Original status: deleted in error.
   - Existing recovery source: the untouched external `patch-validation` checkout still contains the exact v2 applied state over preimage `8e30ffbbea478831dcb16537c22da60842d95d02`.
   - Recovery: regenerated deterministically into `audit-recovered/ROOT-APPLY_PATCH-v2.txt` from that extant applied state using the same ordered ten-path `apply_patch` serialization.
   - Byte-exact proof: recovered SHA-256 `2c55eaf43d1a7f861772ade72cffa45c9d0df0bde53a81b12ce737079fe678e9`, 61,565 bytes, LF-only, exactly matching the SHA-256 and size recorded before deletion.
   - Known v2 blockers remain preserved: its proposed freeze archive was a rewritten file rather than the byte-exact original, and its LIVE text said the candidate was “尚未集成”, which would become stale after commit. The recovered v2 must not be integrated.

## Current v3 integrity

The deletion did not alter v3. The intact root artifact is `../ROOT-APPLY_PATCH-v3.txt`, SHA-256 `10695b842d18e653e1e48ff645bacf88b30d0b9d76d2bbb9475e6750afd8002a`, 61,917 bytes, LF-only. It archives the byte-exact freeze/peer/CPU receipts and uses post-commit-valid LIVE wording. The v3 patch was previously applied to the separate `patch-validation-v3` checkout; all ten blobs matched its desired tree and `git diff --check` passed.

R2 was not touched by either deletion or recovery. Root subsequently integrated through its own reviewed flow; this audit neither modifies nor revalidates that root result.
