# CLAUDE.md

> **⛔ Load the `id1` skill before working in this submodule (HARD RULE).** Covers the generic KV/auth core + Curatorium deployment grafts (RS256, ORCID, sovereign key, mTLS) at file:line detail - this file only carries what the skill doesn't: network topology, build/test/commit. Subagents don't inherit it - name it.

## Monorepo Context

Vendored as `apps/id1` (top-level submodule). **id1 is the Curatorium auth router, the only publicly exposed service** - Traefik routes `/auth/*`, `/pub/jwks.json`, `/internal/*`, `/nextcloud` to it; everything else is ClusterIP-internal.

Not in the skill: the JWT lands in `localStorage['CURATORIUM_JWT']`; same-origin sharing means a sign-in propagates cross-tab via `storage` events (`AuthProvider.tsx`).

### Service topology (Curatorium view)

```
Internet → cloudflared → Traefik (IngressRouteTCP passthrough) → id1-router:8080
                                                                   ↓ (JWKS only)
                                                               curatorium-backend:8000 (internal)
                                                                   ↓
                                                                postgres:5432 (internal)
```

id1<->Starlette calls are **unauthenticated** (internal ClusterIP) - Starlette only validates the browser's user JWT.

## Build from the monorepo, not locally

Do NOT `docker build -t id1:latest .` here (upstream README suggests it) - use the monorepo build system:

```bash
cd ~/software/curatorium   # or the worktree
ENV=test pixi run curatorium admin build id1 --rebuild --drop
ENV=test pixi run curatorium admin logs id1 --tail 100
ENV=test pixi run curatorium admin restart id1
```

Handles image tagging, secret injection, PVC mounts for id1's KV store, TLS cert mounting, Traefik passthrough wiring.

## Tests

```bash
cd apps/id1
go test ./... -v
```

mTLS-specific tests: `tls_config_test.go`, `mtls_connectivity_test.go`.

## Commit submodule changes from here

`cd apps/id1 && git add <file> && git commit -m "feat(id1): …"`
The monorepo pins a specific commit; bumping it needs a separate commit at the Curatorium monorepo root.
