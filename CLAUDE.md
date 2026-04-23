# CLAUDE.md

This file provides guidance to Claude Code when working in the id1 submodule.

## What id1 is (upstream)

id1 is a standalone Go backend, a 9 MB binary providing a generic key/value store with
RSA-keyed identity, JWT authentication, pub/sub, and HTTP bridge. See `README.md` for the
upstream API and command language.

## Monorepo Context

This repo is vendored as `apps/backend/containers/id1` inside the Curatorium monorepo
(typically `~/software/curatorium`). Inside Curatorium, id1 plays one specific role:

**id1 is the Curatorium auth router, the only publicly exposed service.**
All external traffic enters through Traefik at the CURATORIUM_DOMAIN (e.g. `demo.curatorium.app`);
Traefik path-routes `/auth/*`, `/pub/jwks.json`, `/internal/*`, and `/nextcloud` to id1's ClusterIP.
Everything else (Starlette API, PostgreSQL, sync server) is ClusterIP-internal.

### Curatorium-specific auth flow

1. Browser hits id1 for ORCID OAuth OR sovereign-key challenge/response.
2. id1 signs an **RS256 JWT** with claims:
   - `iss = http://id1-router:8080`
   - `aud = curatorium-backend`
   - `sub = ORCID-iD`
   - `kid = JWK Thumbprint` (RFC 7638)
3. JWT is returned to the frontend, stored in `localStorage['CURATORIUM_JWT']`, and sent
   as `Authorization: Bearer` on subsequent API calls. (localStorage is shared across
   tabs on the same origin, so a sign-in in one tab propagates to the others via
   `storage` events; see the frontend's `AuthProvider.tsx` for the listener.)
4. The Curatorium Starlette backend (sibling `containers/starlette`) validates the JWT
   against id1's JWKS endpoint at `id1-router:8080/pub/jwks.json`. RS256 public-key
   verification only, no shared HMAC for JWT validation.

### Key files for the Curatorium integration

- `jwt_signing.go`, RS256 signing, JWKS thumbprint computation.
- `orcid.go`, ORCID OAuth callback handler.
- `sovereign_token.go`, sovereign-key challenge/response for machine-to-machine auth
  (e.g. SLURM BLAST jobs using `~/.config/curatorium/blast_service.pem` on the host).
- `tls_config.go`, SNI-based `GetCertificate` for mTLS. When `MTLS_ENABLED=true`, certs
  are mounted from Kubernetes Secrets.
- `/auth/test_user?orcid=XXXX-XXXX-XXXX-XXXX`, test-only endpoint, enabled **only when
  `ENV=test`**. Used by Playwright E2E tests via `authenticateTestUser(page)` in the
  frontend submodule.

### Service topology (Curatorium view)

```
Internet → cloudflared → Traefik (IngressRouteTCP passthrough) → id1-router:8080
                                                                   ↓ (JWKS only)
                                                               curatorium-backend:8000 (internal)
                                                                   ↓
                                                                postgres:5432 (internal)
```

id1 ↔ Starlette service-to-service calls are **unauthenticated** (internal ClusterIP);
Starlette only validates the user JWT it receives from the browser.

## Build from the monorepo, not locally

Do NOT `docker build -t id1:latest .` from this directory as the upstream README suggests.
Use the Curatorium build system from the monorepo root instead:

```bash
cd ~/software/curatorium   # or the worktree
ENV=test pixi run curatorium admin build id1 --rebuild --drop
ENV=test pixi run curatorium admin logs id1 --tail 100
ENV=test pixi run curatorium admin restart id1
```

The build system handles image tagging, secret injection (`ID1_SHARED_SECRET`, ORCID
client ID/secret, JWT signing keys), PVC mounts for id1's KV store, TLS cert mounting,
and Traefik passthrough wiring.

## Tests

```bash
cd apps/backend/containers/id1
go test ./... -v
```

mTLS-specific tests live in `tls_config_test.go` and `mtls_connectivity_test.go`.

### WebSocket proxying

**`httputil.ReverseProxy` does NOT work for WebSocket.** It passes the HTTP 101 Upgrade
but does not relay bidirectional frames, connections appear to succeed then immediately
disconnect. The `/sync` proxy uses `gorilla/websocket` with a `pumpFrames` goroutine pair
(`sync_proxy.go`). Only `/sync` needs this, `/nextcloud/*` is plain HTTP and uses
`ReverseProxy` correctly.

## Commit submodule changes from here

`cd apps/backend/containers/id1 && git add <file> && git commit -m "feat(id1): …"`
The monorepo pins a specific commit of this submodule; bumping the pin requires a
separate commit in the parent `apps/backend` submodule, and another in the monorepo root.
