# CLAUDE.md

> **Load the `id1` skill before working in this submodule (HARD RULE).** Covers the generic KV/auth core + Curatorium deployment grafts (RS256, ORCID, sovereign key, mTLS) at file and symbol detail - this file only carries what the skill doesn't: network topology, build/test/commit. Subagents don't inherit it - name it.

## Monorepo Context

Vendored as `apps/id1` (top-level submodule). **id1 is the Curatorium auth router**, and one of several Traefik-exposed services (the others are the rclone sidecar on `/data`, apollo on `/apollo`, the frontend as the host catch-all, and the backend on `/api/v0/files/tus` on the browser host and its machine-host callback routes). Traefik routes, by exact path, `/auth/sovereign/token`, `/auth/sovereign/register/begin`, `/auth/sovereign/register/commit`, `/auth/sovereign/devices`, `/auth/orcid`, `/auth/orcid/callback`, `/auth/orcid/exchange` (the browser redeems the one-time login code the callback redirect carries for the JWT), `/auth/refresh`, `/auth/sync_ticket`, `/pub/jwks.json` and `/sync`, plus the `/nextcloud/remote.php/dav` prefix, to id1 (`Config._frontend_traefik_route_yaml`). `/internal/*` is **not** on that list and is reachable only in-cluster; everything else is ClusterIP-internal.

id1 sends `Access-Control-Allow-Origin` only when the request's `Origin` equals the pod variable `CURATORIUM_BROWSER_ORIGIN` exactly. The variable comes from the `curatorium-secrets` key `FRONTEND_URL` (the bare browser origin, distinct from id1's own `FRONTEND_URL` env var, which is the full post-ORCID landing page taken from the secret key `ORCID_FRONTEND_REGISTER_URL`) through a `secretKeyRef` in `apps/backend/k8/templates/3-id1-deployment.yaml.template`, has no default, and id1 refuses to start when it is empty. The same variable gates WebSocket upgrades on both upgraders (the KV socket and `/sync`): an upgrade with no `Origin` header (a non-browser client) or with `Origin` exactly equal to it passes the origin check, and any other is refused with 403. The KV socket checks authentication first, so an unauthenticated KV upgrade is answered with 401 and the challenge, or 404, before the origin check runs; `/sync` checks the origin before it reads the ticket. A KV WebSocket message larger than `KVBodyLimitBytes` closes the connection, and so does a client message larger than `KVBodyLimitBytes` on `/sync` (`SetReadLimit` in `sync_proxy.go`; the backend-to-client direction is not capped). id1 caps every request body at 64 KiB (`DefaultBodyLimitBytes`), raises the key/value route `/{key...}` to 10 MiB (`KVBodyLimitBytes`), applies no cap to the `/nextcloud` WebDAV proxy (`BodyUncapped`), and answers 413 before any handler runs when a request declares a length over its cap; a body with no declared length fails inside the handler once it passes the cap (413 on the key/value route, the handler's own error elsewhere) (`IngressBodyLimits` and `LimitBody` in `limits.go`, wired in `main.go_`).

Not in the skill: the JWT lands in `localStorage['CURATORIUM_JWT']`; same-origin sharing means a sign-in propagates cross-tab via `storage` events (`AuthProvider.tsx`).

### Service topology (Curatorium view)

```
Internet -> cloudflared -> Traefik (TLS-terminating IngressRoute) -> id1-router:8080
                                                                   v (JWKS, /internal/nc-*)
                                                               curatorium-backend:8000 (internal)
                                                                   v
                                                                postgres:5432 (internal)
```

Traefik terminates TLS with the `letsencrypt-wildcard-tls` secret on the `websecure` entry point. The `frontend-sync-to-id1` and `frontend-auth-to-id1` `IngressRoute`s match `Host(<CURATORIUM_DOMAIN>)` plus the paths above and forward to `id1-router:8080`; `machine-host-to-nextcloud` does the same for `/nextcloud/remote.php/dav` on the machine domain, and is rendered only when `MACHINE_DOMAIN` is set. The upstream scheme is `http`, or `https` when `MTLS_ENABLED=true`. The `/sync` route then uses the `id1-insecure` `ServersTransport`; the routes that carry `/nextcloud/remote.php/dav` (`frontend-auth-to-id1`, `machine-host-to-nextcloud` and, on the Nextcloud client hostname, `nextcloud-host-to-id1`) use `id1-proxy-transport`, which presents Traefik's client certificate `traefik-id1-proxy-client` and verifies id1's certificate (`Config._frontend_traefik_route_yaml`, `Config._machine_host_traefik_route_yaml` and `Config._nextcloud_host_traefik_route_yaml`, rendered into `apps/backend/k8/templates/0-traefik-passthrough.yaml.template`, which defines plain `IngressRoute`s despite its name; no `IngressRouteTCP` is involved).

The JWKS read is unauthenticated (internal ClusterIP) - Starlette validates the browser's user JWT against it. The backend's calls to `/internal/nc-token` and `/internal/nc-provision` carry the `X-ID1-Internal-Secret` header, which must equal id1's `ID1_INTERNAL_SECRET`.

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

Do NOT `docker build -t id1:latest .` here (upstream README suggests it) - use the monorepo build system:

```bash
cd ~/software/curatorium   # or the worktree
ENV=test pixi run curatorium k3s build id1 --rebuild --drop
ENV=test pixi run curatorium k3s logs id1 --tail 100
ENV=test pixi run curatorium k3s restart id1
```

Handles image tagging, secret injection, PVC mounts for id1's KV store, TLS cert mounting, Traefik `IngressRoute` wiring.

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
handler for `/pub/jwks.json` in `main.go_` - the backend middleware validates RS256 tokens against
`http://id1-router:8080/pub/jwks.json` (`https` when `MTLS_ENABLED=true`).

## Commit submodule changes from here

`cd apps/id1 && git add <file> && git commit -m "feat(id1): ..."`
The monorepo pins a specific commit; bumping it needs a separate commit at the Curatorium monorepo root.
