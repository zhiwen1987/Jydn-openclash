# Unified advanced proxy notes

## Upstream evidence

The route allowlist is based on Uptime Kuma's own sources rather than an
invented REST surface:

- The deployed, repository-documented Kuma version is 2.5.6. Its official
  router declares history-mode SPA paths including
  `/dashboard`, `/edit`, `/add`, `/list`, `/settings`, `/manage-status-page`,
  `/maintenance`, `/setup`, and `/status/:slug`:
  <https://github.com/louislam/uptime-kuma/blob/2.5.6/src/router.js>
- The official server serves the compiled `dist` tree at `/`, uploads at
  `/upload`, status-page routers under `/api/status-page`, and Socket.IO for
  the authenticated management channel:
  <https://github.com/louislam/uptime-kuma/blob/2.5.6/server/server.js>
- The official internal API documentation says Socket.IO performs the main
  authenticated management flow and documents the public status-page routes:
  <https://github.com/louislam/uptime-kuma/wiki/Internal-API>

No unknown `/api/*` route is proxied. This avoids colliding with the center and
local-source APIs and avoids pretending that Uptime Kuma has a stable general
REST management API.

## Integration contract

Call `proxy_request(handler, access)` only after `/`, `/center-assets/*`,
`/api/center/*`, `/api/local/*`, and `/classic/subscriptions` have been matched.
It returns `False` only for paths it does not own. It writes the entire response
and returns `True` for an owned path, including rejected requests.

The center login cookie must use `Path=/` so it reaches advanced paths. The
proxy checks that session for all LuCI paths and Kuma management paths, then
removes it before forwarding. Kuma public status pages and static files retain
their upstream public behavior. Upstream authentication is never bypassed:
Kuma still requires its Socket.IO login and LuCI still requires its own login
and CSRF tokens.

Upstream cookies are namespaced as `__uc_kuma_*` and `__uc_router_*` in the
browser, then de-namespaced only for the corresponding fixed target. This
prevents one advanced application and the center session from being sent to
the other application.

### Service worker boundary

The unified origin does not enable Uptime Kuma's offline PWA worker. A Kuma
worker registered at the root scope could otherwise control or cache the
center, local-source, and LuCI paths that share this origin. The proxy owns
`/serviceWorker.js` itself: authenticated `GET`/`HEAD` requests receive a
`no-store` retirement worker with only `install`/`activate` lifecycle handlers.
It calls `skipWaiting()` and unregisters itself, and has no request interception,
cache storage, upstream access, navigation, or center-path rewriting. It is
never fetched from Kuma.

The original separately published Kuma endpoint on port `3101` is unchanged
and retains Kuma's original PWA behavior and full standalone functionality.

## Fixed-target and transport boundary

- Kuma is hard-coded to `http://127.0.0.1:3001`.
- LuCI uses an IP-literal private `ROUTER_UI_URL`, preserving explicit HTTP or
  HTTPS, or derives `http://<OPENCLASH_API private IP>:80` from the normal HTTP
  OpenClash API setting. Public, credentialed, hostname, query-bearing, and
  path-bearing target values fail closed.
- Same-target redirects become same-origin relative redirects. Absolute
  redirects to any other scheme, host, or port are blocked.
- POST and WebSocket upgrades require an `Origin` matching a Host listed in
  `LOCAL_SOURCE_HOSTS`. Request bodies, buffered responses, SSE duration, and
  WebSocket idle/lifetime/bytes are bounded.
- Hop-by-hop headers are removed. CSP, upstream authentication challenges, and
  ordinary security headers are preserved. No router secret or Kuma credential
  is generated or injected.

## Isolated verification

`python -m unittest discover -v` in this directory runs the center and proxy
tests. The proxy suite starts only loopback fake upstreams and covers HTTP,
same-origin POST, cookie separation, traversal rejection, redirect policy,
private LuCI target validation, request/response limits, and a real WebSocket
101 handshake with bidirectional tunneled bytes. It does not connect to or
modify production.
