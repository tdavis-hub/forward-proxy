# forward-proxy — prebuilt image

Ready-to-load Docker image of **forward-proxy v1.0.11** (sanitized release).

- `forward-proxy-latest.tar.gz` — the image, **linux/amd64**, tagged `forward-proxy:latest`
- `forward-proxy-latest-arm64.tar.gz` — the image, **linux/arm64**, tagged `forward-proxy:latest`
- `docker-compose.yml` — sample deployment (hardened flags, persistent volume)

> **Pick the file that matches your host architecture:** `uname -m` →
> `x86_64`/`amd64` → use the first file; `aarch64`/`arm64` → use the second.
> Both tag the image `forward-proxy:latest`, so load only the one you need.

## Requirements

Docker with the CLI. ~15 MB disk for the image (it is small on purpose:
statically linked Go binary on a slim Alpine base).

## Load the image

```sh
docker load -i forward-proxy-latest.tar.gz
docker images forward-proxy     # should list forward-proxy:latest
```

## Run

### Option A — Docker Compose (recommended)

```sh
docker compose up -d
```

Then open the admin UI at **http://localhost:8080/admin/** and log in with
the factory default credentials `admin` / `admin123` — **change the password
immediately** (the UI shows a warning banner until you do). Point your
clients at the proxy at `http://<host>:3128` with your proxy user's
credentials (HTTP Basic).

### Option B — plain `docker run`

```sh
docker run -d --name forward-proxy \
  -p 3128:3128 -p 8080:8080 \
  -v forward-proxy-data:/data \
  --read-only --tmpfs /tmp \
  --cap-drop=ALL --security-opt no-new-privileges \
  --restart unless-stopped \
  forward-proxy:latest
```

## What the flags do

| Flag | Purpose |
|---|---|
| `-p 3128:3128` | Proxy port (clients set this as their HTTP/HTTPS proxy) |
| `-p 8080:8080` | Admin UI + API |
| `-v …:/data` | Persistent state: `config.json`, `activity.jsonl`, `audit.log` |
| `--read-only --tmpfs /tmp` | Read-only root filesystem; all writes go to `/data` |
| `--cap-drop=ALL` | Runs with zero Linux capabilities |
| `--security-opt no-new-privileges` | Processes cannot escalate privileges |
| `--restart unless-stopped` | Survives reboots/crashes |

The image runs as a non-root user and includes a built-in healthcheck
(`GET /healthz` on the proxy port).

## Notes

- **Sessions don't survive a container restart** — the HMAC signing key is
  regenerated on boot; just log in again.
- Optional **TLS for the admin UI**: mount PEM files and set
  `TLS_CERT_FILE` / `TLS_KEY_FILE` (see the compose file for the shape).
- Full feature documentation (users, rules, quotas, CSV export, audit log):
  see the main project `README.md`.

## Verifying the image

```sh
docker run --rm forward-proxy:latest   # prints version banner + starts
curl -s http://127.0.0.1:3128/healthz  # 200 once running
```

To confirm the architecture of a loaded image (should match your host):

```sh
docker image inspect forward-proxy:latest --format '{{.Architecture}}'
```
