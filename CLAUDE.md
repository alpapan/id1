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
ENV=test pixi run curatorium k3s build id1 --rebuild --drop
ENV=test pixi run curatorium k3s logs id1 --tail 100
ENV=test pixi run curatorium k3s restart id1
```

Handles image tagging, secret injection, PVC mounts for id1's KV store, TLS cert mounting, Traefik passthrough wiring.

## This checkout IS the fork

`apps/id1` is a checkout of `https://github.com/alpapan/id1.git` (`origin`, branch `main`) - not a
separate source from "the fork". Submodule commits are pushed to that fork's `origin/main` so the
monorepo pointer references a reachable SHA. `annot8r_id1`, the standalone auth authority for
annot8r_uniprot, is built from the SAME fork source (`main.go_` renamed to `main.go`, built as a
separate Go module with a `replace` onto the id1 lib, mirroring `apps/id1/Dockerfile`); there is no
separate annot8r_id1 repo, and a standalone host builds it by cloning the fork directly.

## Tests

```bash
cd apps/id1
go test ./... -v
```

mTLS-specific tests: `tls_config_test.go`, `mtls_connectivity_test.go`.

**`main.go_` is a Docker build template, not a Go artefact.** The Dockerfile copies it to
`/go/src/cmd/main.go` where it compiles as a separate `id1-main` module; because it is never part of
the on-disk `id1` package, `go test ./...` never compiles it. Logic placed there is unreachable by
the test suite - extract it into the `id1` package as an exported function and call it from
`main.go_` (pattern: `id1.IsDevOrTestEnv(env string) bool` in `jwt_signing.go`, tested in
`jwt_signing_test.go`). Config resolution lives in `config.go` `ResolveConfig(getenv)`
(`PORT` then `ID1_AUTH_PORT` then 8080; `DBPATH` then `/mnt/id1db`), unit-tested in `config_test.go`.

`HandleJWKS()` is defined in `jwt_signing.go` but only serves traffic once registered as an HTTP
handler for `/pub/jwks.json` in `id1.go` - the backend middleware validates RS256 tokens against
`http://id1:8001/pub/jwks.json`.

## Commit submodule changes from here

`cd apps/id1 && git add <file> && git commit -m "feat(id1): …"`
The monorepo pins a specific commit; bumping it needs a separate commit at the Curatorium monorepo root.
