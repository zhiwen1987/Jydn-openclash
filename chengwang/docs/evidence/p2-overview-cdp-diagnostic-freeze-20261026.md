# Chengwang overview CDP failure diagnostic freeze

- Preimage commit: `8e30ffbbea478831dcb16537c22da60842d95d02`
- Preimage tree: `50a361fa8a2f3daeebfc2670499783a8da12c650`
- Afterimage commit: `125dec6d27005eed60ebb50efeb8cbc5c55627ac`
- Afterimage tree: `db6351497f9c3563bf6ada70ac97482d17aa38ab`
- Clean LF afterimage: `D:/CodexData/workspace/chengwang-overview-cdp-diagnostic-125dec6-sourcegit`
- Full patch: `0001-test-chengwang-bound-CDP-target-failure-diagnostics.patch`
- Full patch SHA-256: `af2b8c74a7f0924830cc5affa3c157d9e7f41be5184b8c486e5e427debb6b90c`
- Full patch bytes: `49640`
- Source-bound CPU report: `D:/CodexData/workspace/chengwang-overview-cdp-diagnostic-125dec6-report.json`
- CPU report SHA-256: `1bda783fbd6fb6e6fe7254515ecf0f7ce52bd4eff00589ffa21c6cafc83a1237`
- Validation: nine suites, 236 passed, 0 skipped; report explicitly records `realBrowserProven=false`, `realProductServerProven=false`, `production=false`, and `authorization=BLOCKED`.
- Patch checks: reverse apply check at the afterimage passed; `git diff --check` passed.
- Guard proof: the exact `TargetGuard` class section SHA-256 is unchanged at `48fd0312843f8f17c19a8924160d45e772841d9a74a1fee46cdef358642c2a19` in both preimage and afterimage.
- Workflow proof: `.github/workflows/chengwang-overview-ui-browser.yml` is unchanged; Git blob `2e1295f002fa497f9e6b4e5c7c82c61adffaf430` in both preimage and afterimage.

## Scope

The failure-only native diagnostic schema is bumped to v2. It projects only bounded target-type counts, three booleans for row and identifier validity, closed target-kind labels, and a closed first-failing guard predicate from the already obtained `Target.getTargets` values. It does not add a browser RPC, wait, retry, authorization, target whitelist, page/root relaxation, or successful evidence field.

Exactly six source files changed:

1. `chengwang/tools/browser-scene-driver/native-session.mjs`
2. `chengwang/tools/browser-scene-driver/test-native-session.mjs`
3. `chengwang/tools/overview-ui-browser/ui-driver.mjs`
4. `chengwang/tools/overview-ui-browser/test-ui-driver.mjs`
5. `chengwang/deploy/overview-ui-browser/overview_ui_scene.py`
6. `chengwang/deploy/overview-ui-browser/test_overview_scene.py`

No React, CSS, workflow, product API, server, production, main branch, or Registry file changed. No target identifier, URL, origin, debugger or WebSocket address, header, token, raw exception text, or session material is emitted or hashed by the new diagnostic.

## Remaining boundary

The latest source-bound real browser evidence remains run `40103042172` at preimage `8e30ffb`: both Playwright profiles and their fresh replays passed, while both Chrome/CDP profiles failed before the first UI checkpoint. This candidate has not run a browser, product server, build, Linux isolation, or CI. Only a new isolated Linux CI run on the integrated exact commit can determine the two CDP profiles' current target composition and rejection predicate.
