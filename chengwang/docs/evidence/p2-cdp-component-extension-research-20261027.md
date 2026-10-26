# Chrome CDP component-extension startup repair research

## Scope and evidence boundary

- Formal source base: `23fe731c072ac50aaaf9ef9479c0eaf0c1c1885e`.
- Original evidence: `D:/CodexData/workspace/chengwang-overview-browser-40370667458-originals-20261027-native56h-v1`.
- N's final evidence receipt is pinned by SHA-256 `06ee3d83bfea3692731730b0d9ab9856bd28329008c0af2673230d3dfdbefab3`.
- Both Chrome-CDP profiles stop at `CDP_POST_TARGETS` with `UNAUTHORIZED_PROTECTED`, zero UI checkpoints, two extra `service_worker` targets, two `CHROME_EXTENSION` scheme classifications, two missing openers, and two context matches to each reference. Context and scheme are observations only; they do not authorize ownership.
- Both Playwright profiles complete. Their producer records report `Chrome/157.0.8103.6`, revision `41520584daa68d0040db7746ae562a0ff82187f6`, protocol `1.3`, and executable SHA-256 `ec4e78d65a5382c2b50aaf28c6a655a624973b3d3c711a2a4ae34369fd9a3444`.
- Each Chrome-CDP profile's pin-consumption record stages the same executable SHA-256. The failing CDP path stops before its own `Browser.getVersion`/process-identity record, so the CDP version is linked through the identical staged executable and source pin, not represented as a direct CDP version read.
- The exact source-bound direct-CDP launch vector includes `--disable-extensions` but not `--disable-component-extensions-with-background-pages`. The failed artifact does not publish raw argv; this is a source-bound launch-vector fact, not an independent argv readback.

## Primary-source findings

1. Chromium exact tag `157.0.8103.6` declares `disable-component-extensions-with-background-pages` specifically for default component extensions with background pages:
   - https://github.com/chromium/chromium/blob/157.0.8103.6/chrome/common/chrome_switches.h
2. The same exact tag's `ComponentLoader::AddDefaultComponentExtensionsWithBackgroundPages` checks that switch and returns before adding the relevant component extensions:
   - https://github.com/chromium/chromium/blob/157.0.8103.6/chrome/browser/extensions/component_loader.cc
3. Chromium's component-extension documentation distinguishes bundled component extensions from ordinary/default-installed extensions and notes that users cannot disable component extensions:
   - https://chromium.googlesource.com/chromium/src/+/main/extensions/docs/component_extensions.md
4. Google's Chrome tooling flag guide explicitly says this switch disables built-in extensions not affected by `--disable-extensions`:
   - https://github.com/GoogleChrome/chrome-launcher/blob/main/docs/chrome-flags-for-tools.md
5. The repository pins Playwright git commit `20a2087ea43412b90c172c88faef80786ee18b8b`. Its exact `chromiumSwitches.ts` includes `--disable-component-extensions-with-background-pages` among default Chromium arguments:
   - https://github.com/microsoft/playwright/blob/20a2087ea43412b90c172c88faef80786ee18b8b/packages/playwright-core/src/server/chromium/chromiumSwitches.ts

## Adaptation and limits

- The source evidence explains the observed engine split: Playwright supplies the dedicated component-extension switch by default; the direct CDP launcher does not.
- The candidate adds the switch only to the direct `chrome-cdp` spawn. It does not change the shared Playwright argument list.
- `TargetGuard`, target authorization, CDP commands, ordering, retries, waits, timeouts, schemas, diagnostics, page code, and business behavior remain unchanged.
- This is a strong source-backed causal hypothesis, not runtime proof. Only an exact-candidate isolated Chrome-CDP CI run can show that Chrome 157 starts without the two protected workers and that both profiles complete.
- If extra protected targets remain, the guard must continue rejecting; no target may be whitelisted from scheme or context alone.
