# CLAUDE.md

> **⛔ Load the `id1` skill before working in this submodule (HARD RULE).** It covers the generic KV/auth core AND the Curatorium deployment grafts (RS256 signing, ORCID, sovereign key, mTLS) in full file:line detail - this file only carries what the skill doesn't: the Curatorium network topology and build/test/commit mechanics. Subagents do not inherit it - name it in the dispatch prompt.

## Monorepo Context

Vendored as `apps/id1` (top-level submodule). **id1 is the Curatorium auth router, the only publicly exposed service** - Traefik path-routes `/auth/*`, `/pub/jwks.json`, `/internal/*`, `/nextcloud` to it; everything else is ClusterIP-internal.

One fact not in the skill: the JWT lands in `localStorage['CURATORIUM_JWT']`, and since `localStorage` is shared across same-origin tabs, a sign-in in one tab propagates to others via `storage` events (frontend's `AuthProvider.tsx`).

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
cd apps/id1
go test ./... -v
```

mTLS-specific tests live in `tls_config_test.go` and `mtls_connectivity_test.go`.

## Commit submodule changes from here

`cd apps/id1 && git add <file> && git commit -m "feat(id1): …"`
The monorepo pins a specific commit of this submodule; bumping the pin requires a
separate commit in the Curatorium monorepo root.
