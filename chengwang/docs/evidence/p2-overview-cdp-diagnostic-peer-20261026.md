# Independent peer review: failure-only Chrome/CDP target diagnostic schema v2

- Candidate: `125dec6d27005eed60ebb50efeb8cbc5c55627ac`
- Preimage: `8e30ffbbea478831dcb16537c22da60842d95d02`
- Method: exact six-file diff and source/test inspection; pure CPU Node/Python tests only. No browser, server, build, npm, Go, network, GitHub, raw log, or session search was used.

## Result

No blocker found.

The producer emits only closed stages/faults/predicates/kinds, bounded counts and booleans. Target IDs, URLs/origins, debugger or WebSocket endpoints, headers/tokens, raw exceptions, and session material are neither emitted nor hashed. Exact top-level and nested keys are enforced in both JavaScript and Python, and schema v1 is rejected.

The first-predicate ordering in `projectInitialTargets` matches `TargetGuard.freezeInitial`: input bounds, row, ID, type, duplicate ID, protected non-page, page count, then initial page URL. The ordering in `projectPostTargets` matches `TargetGuard.setBaseline`: input bounds, row, ID, type, duplicate ID, selected page, selected differs from initial, initial page, then unauthorized protected target. Diagnostic projection occurs before the corresponding guard rejection without authorizing a target or changing RPC ordering.

The success path does not call the diagnostic sink. Runtime guard logic, target discovery sequence, allowed browser RPCs, timing limits, trust/auth settings, and Playwright launch/baseline behavior are unchanged by the candidate diff.

## Evidence

- Producer and validator: `chengwang/tools/browser-scene-driver/native-session.mjs:47-177,203-283,334-493`
- JS reader and failure-only publication: `chengwang/tools/overview-ui-browser/ui-driver.mjs:20-44,152-178`
- Python reader: `chengwang/deploy/overview-ui-browser/overview_ui_scene.py:263-359`
- JS tests: `chengwang/tools/browser-scene-driver/test-native-session.mjs:63-206`; `chengwang/tools/overview-ui-browser/test-ui-driver.mjs:77-105`
- Python tests: `chengwang/deploy/overview-ui-browser/test_overview_scene.py:170-294`
- `git diff --check` passed; candidate worktree remained clean.
- `node --test .../test-native-session.mjs .../test-ui-driver.mjs`: 50 passed, 0 failed.
- `python -m unittest .../test_overview_scene.py`: 16 passed, 0 failed.

## Residual risk

Per review constraints, no real Chrome/CDP or Playwright startup/failure was exercised. The remaining risk is integration-only: actual CDP payload/proxy shapes and private diagnostic-file publication/readback under the CI filesystem were verified by source contracts and CPU fixtures, not by a live browser run.
