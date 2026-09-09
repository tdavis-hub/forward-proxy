# forward-proxy

A lightweight, self-contained **HTTP/HTTPS forward proxy** with a web-based
management interface, written in pure Go (zero external dependencies, single
static binary, small Alpine image).

## Features

- **Forward proxying**
  - Plain HTTP via absolute-form requests (`http://host/`)
  - HTTPS via `CONNECT` + bidirectional tunneling
  - Per-request timeouts, upstream connection pooling
- **Access control & user management**
  - Per-user HTTP Basic credentials (PBKDF2-SHA256, 600k iterations for new hashes)
  - Roles: `user` and `admin` (only admins can open the management UI)
  - Enable/disable users, per-user or global concurrent-connection caps
  - Per-user daily traffic caps (MB, reset each day)
- **Whitelist / blacklist**
  - Global and per-user rule lists
  - Pattern types: exact host (`example.com`), wildcard (`*.example.com` —
    matches the domain *and* all subdomains), globs (`*` / `?`), CIDR
    (`10.0.0.0/8`) and bare IPs
  - Precedence: **global blacklist → user blacklist → whitelist (user +
    global union) → allow**. If any whitelist is non-empty, or
    *whitelist-only* mode is on, everything else is denied. Blacklist always
    wins.
- **Management interface** (web UI, served on the admin port)
  - Dashboard: live totals, per-user usage, recent activity
  - Statistics: dependency-free canvas charts — requests over time
    (allowed / denied / errors), data egress per bucket, and top users by
    data, with selectable window (1 h / 6 h / 24 h / 7 d) and per-user
    filter, aggregated from the activity ring buffer
  - Users: full CRUD, roles, password reset, per-user rules & caps
  - Global rules, connection/timeout settings, log settings
  - Activity log: filter by user/text, CSV export
  - Stateless HMAC session tokens (cookie-scoped to `/admin`, 12 h TTL;
    sessions don't survive a container restart — the signing key is
    regenerated on boot, so admins simply log in again)
- **Activity logging**: in-memory ring buffer + rotating JSONL file,
  per-request outcome (ALLOWED / DENIED / CONNECT / ERROR), byte counts,
  durations.
- **Live configuration**: rule/timeout changes apply without restart;
  changing a listen address rebinds the listener on the fly.

## Quick start

```sh
docker run -d --name proxy \
  -p 3128:3128 \
  -p 8080:8080 \
  -v proxy-data:/data \
  --read-only --tmpfs /tmp \
  --cap-drop=ALL --security-opt no-new-privileges \
  --restart unless-stopped \
  forward-proxy:1.0.11
```

Pin the image to a version tag (not `latest`) for reproducible deploys, and
`--restart unless-stopped` brings the proxy back after a reboot or crash.

The flags are defense-in-depth: read-only root filesystem (state lives only in
the `/data` volume), all capabilities dropped, and `no-new-privileges`. To
serve the admin UI over TLS instead of plaintext, mount PEM files and set the
environment:

```sh
docker run -d --name proxy \
  -p 3128:3128 -p 8443:8080 \
  -v proxy-data:/data -v /etc/ssl/proxy:/tls:ro \
  -e TLS_CERT_FILE=/tls/cert.pem -e TLS_KEY_FILE=/tls/key.pem \
  --read-only --tmpfs /tmp --cap-drop=ALL --security-opt no-new-privileges \
  forward-proxy:latest
```

- Proxy port: **3128** — clients use this as their HTTP proxy
- Admin UI: **http://localhost:8080/admin/** — default credentials
  `admin` / `admin123` (change immediately; the UI warns while the default
  password is in use)
- State lives in the `/data` volume (`config.json`, `activity.jsonl`,
  `audit.log`)

### Using it as a proxy

```sh
# plain HTTP through the proxy (authenticated)
curl -x http://admin:admin123@localhost:3128 http://example.com

# HTTPS through the proxy (CONNECT)
curl -x http://admin:admin123@localhost:3128 https://example.com
```

Or in a browser / system: set the HTTP proxy to `host:3128` and enter the
user's credentials when prompted.

## Building the image

```sh
docker build -t forward-proxy:latest .
```

The image is multi-stage (`golang:1.22-alpine` → `alpine:3.21`), ships a
statically linked binary, runs as a non-root user, and has a built-in
healthcheck (`GET /healthz` on the proxy port, which is never TLS).

### Prebuilt images (no build required)

Prebuilt images for both `linux/amd64` and `linux/arm64` are committed under
`release/`, so you can load one directly without building:

| File | Architecture |
|---|---|
| `release/forward-proxy-latest.tar.gz` | `linux/amd64` |
| `release/forward-proxy-latest-arm64.tar.gz` | `linux/arm64` |

Pick the one matching your host (`uname -m` → `x86_64`/`amd64` or
`aarch64`/`arm64`). Both are tagged `forward-proxy:latest`:

```sh
docker load -i release/forward-proxy-latest-arm64.tar.gz   # or the amd64 file
docker images forward-proxy     # should list forward-proxy:latest
```

Then run via `docker compose -f release/docker-compose.yml up -d`, or plain
`docker run` — full details in [`release/README.md`](release/README.md).

## Configuration reference

Everything is managed through the web UI; the same data is stored in
`/data/config.json` (atomic writes).

| Setting | Meaning |
|---|---|
| `proxy.enabled` | Master switch; when off the proxy port refuses traffic |
| `proxy.listen_addr` | Proxy listen address (`:3128`) |
| `proxy.admin_listen_addr` | Admin UI/API listen address (`:8080`) |
| `proxy.require_auth` | Require Basic credentials for proxied traffic |
| `proxy.allow_http` / `proxy.allow_https` | Enable plain-HTTP / CONNECT |
| `proxy.connect_timeout_sec` | Upstream connect timeout (default 15 s) |
| `proxy.read_timeout_sec` | Per-request idle timeout (default 300 s) |
| `proxy.default_max_conns` | Per-user concurrent-connection cap (0 = unlimited) |
| `proxy.max_global_conns` | Global concurrent-connection cap (0 = unlimited) |
| `global_rules.whitelist_only` | Deny-by-default for all users |
| `global_rules.whitelist` / `global_rules.blacklist` | Global pattern lists |
| `user.whitelist_only` / `user.whitelist` / `user.blacklist` | Per-user rules |
| `user.max_conns` | Per-user connection cap override |
| `user.daily_traffic_mb` | Per-user daily data cap (0 = unlimited) |
| `logs.ring_size` / `logs.file_max_mb` / `logs.to_file` | Log buffering, file size limit, file logging on/off |

### Rule patterns

| Pattern | Matches |
|---|---|
| `example.com` | exactly `example.com` |
| `*.example.com` | `example.com` and every subdomain |
| `api.*.example.com` | any host of the form `api.X.example.com` |
| `*evil*` | any host containing `evil` |
| `10.0.0.0/8` | any IP in the CIDR |
| `192.168.1.1` | that single IP |

Ports in requests are stripped before matching; hosts are case-insensitive.

## Environment variables / flags

| Variable | Flag | Default |
|---|---|---|
| `DATA_DIR` | `-data` | `/data` |

## Endpoints

- `GET /admin/healthz` — liveness probe (unauthenticated)
- `GET /admin/` — management UI (single page)
- `/admin/api/*` — JSON API (login, self, status, users, global-rules,
  settings, logs, logs/export, stats/timeline), guarded by admin
  session/Bearer/Basic auth
  - `GET /admin/api/stats/timeline?hours=24[&bucket=60][&user=NAME]` —
    time-bucketed request/byte totals with allowed/denied/error counts and
    per-user top-10 (powers the dashboard charts)

## Development

```sh
go build ./...     # build
go test ./...      # unit tests (rules engine, auth, tokens)
```
