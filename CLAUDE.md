# CLAUDE.md

> **Load the `id1` skill before working in this submodule (HARD RULE).** Covers the generic KV/auth core and the Curatorium deployment grafts (RS256, ORCID, sovereign key, mTLS) at file and symbol detail. This file carries network topology, build, test and commit notes.

## Monorepo Context

- Vendored as `apps/id1` (top-level submodule). id1 is the Curatorium auth router and one of several Traefik-exposed services; the others are the rclone sidecar on `/data`, apollo on `/apollo`, the frontend as the host catch-all, and the backend on `/api/v0/files/tus` on the browser host plus its machine-host callback routes.
- Traefik routes these to id1 by exact path (`Config._frontend_traefik_route_yaml`):
  - `/auth/sovereign/token`, `/auth/sovereign/register/begin`, `/auth/sovereign/register/commit`, `/auth/sovereign/devices`
  - `/auth/orcid`, `/auth/orcid/callback`, `/auth/orcid/exchange` (the browser redeems the one-time login code the callback redirect carries for the JWT)
  - `/auth/refresh`, `/auth/sync_ticket`, `/pub/jwks.json`, `/sync`
  - plus the `/nextcloud/remote.php/dav` prefix
- `/internal/*` is not on that list: reachable only in-cluster. Everything else is ClusterIP-internal.
- CORS: `Access-Control-Allow-Origin` is sent only when the request's `Origin` equals the pod variable `CURATORIUM_BROWSER_ORIGIN` exactly.
  - The variable comes from the `curatorium-secrets` key `FRONTEND_URL` (the bare browser origin) through a `secretKeyRef` in `apps/backend/k8/templates/3-id1-deployment.yaml.template`. It has no default; id1 refuses to start when it is empty.
  - That secret key is distinct from id1's own `FRONTEND_URL` env var, the full post-ORCID landing page taken from the secret key `ORCID_FRONTEND_REGISTER_URL`.
- WebSocket origin: the same variable gates both upgraders (the KV socket and `/sync`). An upgrade with no `Origin` header (non-browser client) or an `Origin` exactly equal to it passes; any other gets 403.
  - The KV socket checks authentication first: an unauthenticated KV upgrade gets 401 with the challenge, or 404, before the origin check.
  - `/sync` checks the origin before it reads the ticket.
- Message caps: a KV WebSocket message larger than `KVBodyLimitBytes` closes the connection; so does a client message larger than `KVBodyLimitBytes` on `/sync` (`SetReadLimit` in `sync_proxy.go`; the backend-to-client direction is not capped).
- Request body caps (`IngressBodyLimits` and `LimitBody` in `limits.go`, wired in `main.go_`):
  - Every request: 64 KiB (`DefaultBodyLimitBytes`). Key/value route `/{key...}`: 10 MiB (`KVBodyLimitBytes`). `/nextcloud` WebDAV proxy: no cap (`BodyUncapped`).
  - A request that declares a length over its cap gets 413 before any handler runs.
  - A body with no declared length fails inside the handler once it passes the cap: 413 on the key/value route, the handler's own error elsewhere.
- Not in the skill: the JWT lands in `localStorage['CURATORIUM_JWT']`; `localStorage` is per-origin, so a sign-in reaches other tabs via `storage` events (`apps/frontend/src/lib/auth/AuthProvider.tsx`).

### Service topology (Curatorium view)

```
Internet -> cloudflared -> Traefik (TLS-terminating IngressRoute) -> id1-router:8080
                                                                   v (JWKS, /internal/nc-*)
                                                               curatorium-backend:8000 (internal)
                                                                   v
                                                                postgres:5432 (internal)
```

- The `frontend-sync-to-id1` and `frontend-auth-to-id1` `IngressRoute`s match `Host(<CURATORIUM_DOMAIN>)` plus the paths above and forward to `id1-router:8080`.
- `machine-host-to-nextcloud` does the same for `/nextcloud/remote.php/dav` on the machine domain, rendered only when `MACHINE_DOMAIN` is set.
- Upstream scheme is `http`, or `https` when `MTLS_ENABLED=true`. The `/sync` route then uses the `id1-insecure` `ServersTransport`; the routes that carry `/nextcloud/remote.php/dav` (`frontend-auth-to-id1`, `machine-host-to-nextcloud` and, on the Nextcloud client hostname, `nextcloud-host-to-id1`) use `id1-proxy-transport`, which presents Traefik's client certificate `traefik-id1-proxy-client` and verifies id1's certificate.
- Rendered by `Config._frontend_traefik_route_yaml`, `Config._machine_host_traefik_route_yaml` and `Config._nextcloud_host_traefik_route_yaml` into `apps/backend/k8/templates/0-traefik-passthrough.yaml.template` (its header documents the TLS secret and the matchers); plain TLS-terminating `IngressRoute`s despite the name, no `IngressRouteTCP`.
- The JWKS read is unauthenticated (internal ClusterIP); Starlette validates the browser's user JWT against it.
- The backend's calls to `/internal/nc-token` and `/internal/nc-provision` carry the `X-ID1-Internal-Secret` header, which must equal id1's `ID1_INTERNAL_SECRET`.

### The `/nextcloud` proxy and the caller address

The `/nextcloud` and `/nextcloud/` routes (registered in `main.go_` only when `NEXTCLOUD_PROXY_URL` is non-empty) reverse-proxy public WebDAV to Nextcloud's id1-only TLS port 8087 and state the caller's address in `X-Curatorium-Client-Address`, so Nextcloud's brute-force protection counts each caller separately. The proxy refuses a request whose address it cannot believe: it never forwards without one. The rule, the two edge-proof methods and the checks that halt a deployment are in `docs/authentication.md` ("Caller address", "Setting up and rotating the edge proof"). The rule lives in:

| File | Holds |
|---|---|
| `nc_client_address.go` | `ClientAddressRule.Decide` (which address to state, or 400/403) and `ApplyClientAddress` (strips the caller's own `X-Curatorium-Client-Address` and `X-Curatorium-Edge`, and the `Connection` tokens naming them) |
| `connector_set.go` | the `cloudflared-connectors.kube-system.svc.cluster.local` lookup behind the `connector-address` proof (5 s cache) |
| `traefik_proof.go` | `RequestFromTraefik`: a verified chain with leaf common name `traefik-id1-proxy-client` ending at the `TRAEFIK_PROXY_CA_FILE` certificate |
| `nc_proxy.go` | `ResolveNextcloudProxyConfig` (reads and validates the variables below) and the proxy handler |

The variables have no defaults. They are read only when `NEXTCLOUD_PROXY_URL` is set, and then a missing or invalid one stops id1 at start (`log.Fatalf` in `main.go_`), except where the right-hand column says otherwise. The deployment sets them in `apps/backend/k8/templates/3-id1-deployment.yaml.template`.

| Variable | Meaning | When unset |
|---|---|---|
| `NEXTCLOUD_PROXY_URL` | https URL of Nextcloud's id1-only port (`https://nextcloud:8087`) | the `/nextcloud` proxy is not registered and id1 starts; non-https stops id1 |
| `EDGE_PROOF_METHOD` | `connector-address` or `edge-secret` | stops id1 (when the proxy is registered); the manifest render halts first |
| `EDGE_PROOF_SECRET` | compared with `X-Curatorium-Edge` under `edge-secret`; from `curatorium-secrets` | stops id1 under `edge-secret`; ignored under `connector-address` |
| `CLUSTER_POD_CIDR` | the pod range; a caller address inside it is refused (400) | stops id1 |
| `MTLS_ENABLED` | `true` requires Traefik's client certificate on `/nextcloud`; any other value requires none and logs a warning at start | off |
| `TRAEFIK_PROXY_CA_FILE` | PEM CA that signs Traefik's certificate (`id1-proxy-mtls-ca`); also added to the listener's client CAs | stops id1 when `MTLS_ENABLED=true` |
| `NEXTCLOUD_CLIENT_CERT_FILE`, `NEXTCLOUD_CLIENT_KEY_FILE` | id1's client certificate for Nextcloud (`id1-nextcloud-client`), required whatever `MTLS_ENABLED` says | stops id1 |
| `NEXTCLOUD_SERVER_CA_FILE` | the only CA id1 trusts for Nextcloud's server certificate | stops id1 |

id1's `/internal/nc-token` and `/internal/nc-provision` calls to Nextcloud use `NEXTCLOUD_URL` (port 80) and do not pass through this proxy. Tests: `nc_client_address_test.go`, `connector_set_test.go`, `traefik_proof_test.go`, `nc_proxy_test.go`, `tls_config_traefik_ca_test.go` and `main_nextcloud_proxy_integration_test.go`.

## Build from the monorepo, not locally

- Do NOT `docker build -t id1:latest .` here (the upstream README suggests it). The monorepo build handles image tagging, secret injection, PVC mounts for id1's KV store, TLS cert mounting and Traefik `IngressRoute` wiring.
- From the monorepo root (host) or the worktree: `ENV=test pixi run curatorium k3s build id1 --rebuild --drop`; then `k3s diag logs id1 --tail 100` and `k3s lifecycle restart id1` under the same `ENV=test pixi run curatorium` prefix.

## This checkout IS the fork

- `apps/id1` is a checkout of `https://github.com/alpapan/id1.git` (`origin`, branch `main`), not a separate source from "the fork".
- Submodule commits are pushed to the fork's `origin/main` so the monorepo pointer references a reachable SHA.
- `annot8r_id1` (the standalone auth authority for annot8r_uniprot) is built from the SAME fork source: `main.go_` renamed to `main.go`, built as a separate Go module with a `replace` onto the id1 lib, mirroring `apps/id1/Dockerfile`.
- There is no separate annot8r_id1 repo; a standalone host builds it by cloning the fork directly.

## Tests

- Run the declared task: `ENV=test pixi run -m apps/id1/pixi.toml test`; add `test-testmint`, `test-curatoriumdemo` and `test-integration` where the change touches those handlers or `main.go_` (a bare `go test` compiles neither mint handler). One test: `go test -run <name> -v` from `apps/id1`.
- mTLS-specific tests: `tls_config_test.go`, `mtls_connectivity_test.go`.
- **`main.go_` is a Docker build template, not a Go artefact.**
  - The Dockerfile's build stage copies it in (`COPY main.go_ /go/src/cmd/main.go`) and compiles it as a separate `id1-main` module. It is never part of the on-disk `id1` package, so `go test ./...` never compiles it.
  - Logic placed there is unreachable by the test suite: extract it into the `id1` package as an exported function and call it from `main.go_` (pattern: `id1.IsDevOrTestEnv(env string) bool` in `jwt_signing.go`, tested in `jwt_signing_test.go`).
- Config resolution is `ResolveConfig(getenv)` in `config.go` (`PORT`, then `ID1_AUTH_PORT`, then 8080; `DBPATH`, then `/mnt/id1db` (pod)), unit-tested in `config_test.go`.
- `HandleJWKS()` (in `jwt_signing.go`) serves traffic only once registered for `/pub/jwks.json` in `main.go_`. The backend middleware validates RS256 tokens against `http://id1-router:8080/pub/jwks.json` (`https` when `MTLS_ENABLED=true`).

## Commits

- `apps/id1` is a submodule (the fork's `main`, see above); the monorepo pins a specific commit of it.
- Commit from the monorepo root, one commit per program (root `CLAUDE.md`): stage files explicitly (`git add apps/id1/<file>`) and end the message with the `Claude-Session:` trailer the root file requires.
