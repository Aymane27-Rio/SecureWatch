# SecureWatch

SecureWatch is a modular Linux security monitoring toolkit. It runs local checks, parses authentication logs, creates JSON and HTML reports, and can display scan data in a web dashboard with Prometheus and Grafana.

## Features

- Bash checks for accounts, listening ports, firewall state, package updates, AIDE, and rkhunter.
- SSH and sudo anomaly parsing with structured JSON events.
- HTML reports and a FastAPI service that stores reports and events in SQLite.
- React dashboard, Prometheus exporter, and starter Grafana dashboard.
- Optional AWS security group audit module.

## Run with Docker Compose

Prerequisites: Docker Engine and the Docker Compose plugin.

```bash
install -d -m 700 data/logs data/reports data/state
chmod 700 data data/logs data/reports data/state
if [ ! -f .env ]; then
  (
    umask 077
    printf 'WEBAPI_API_KEY=%s\nSECUREWATCH_UID=%s\nSECUREWATCH_GID=%s\nGRAFANA_ADMIN_PASSWORD=%s\n' \
      "$(openssl rand -hex 32)" "$(id -u)" "$(id -g)" "$(openssl rand -hex 32)" > .env
  )
fi
chmod 600 .env
docker compose up --build -d
```

If `.env` already exists from an earlier setup, add `SECUREWATCH_UID`, `SECUREWATCH_GID`, and `GRAFANA_ADMIN_PASSWORD` once. Use the values from `id -u` and `id -g` for the UID/GID, and generate the Grafana password with `openssl rand -hex 32`. If earlier scans created root-owned files, restore ownership to your account and restrict the generated data with:

```bash
sudo chown -R "$(id -u):$(id -g)" data/logs data/reports data/state
chmod 700 data data/logs data/reports data/state
find data/logs data/reports data/state -type d -exec chmod 700 {} +
find data/logs data/reports data/state -type f -exec chmod 600 {} +
```

Grafana reads the configured password when its data volume is first initialized; an existing Grafana volume keeps its current login.

Host-published services bind only to loopback:

- Dashboard: <http://127.0.0.1:3000>
- API: <http://127.0.0.1:8000> (data routes require `X-API-Key`; `/hello` is public)
- Alternate file-backed API: <http://127.0.0.1:8001> (optional; data routes require `X-API-Key`)
- Prometheus: <http://127.0.0.1:9090>
- Grafana: <http://127.0.0.1:3001>
- Exporter metrics are available to Prometheus on the internal Compose network.

To start only the alternate API service, use its opt-in Compose profile:

```bash
docker compose --profile alternate-api up --build -d alternate-api
```

This starts only the alternate API service. It uses the same local API key, reads `data/logs` read-only, and binds to loopback on port 8001.

Run a scan from the repository root with `make run`. Reports and logs appear under `data/`; the API imports new event files automatically. A few checks use `sudo` for full visibility. The API requires the configured `X-API-Key` for report and event routes, so keep the Compose ports loopback-only. For remote dashboard access, use a host-based reverse proxy with TLS and authentication, targeting `127.0.0.1:3000`; do not publish the API, Prometheus, Grafana, or exporter ports directly.

Both API images and the metrics exporter run as the configured host UID/GID without Linux capabilities. The primary API container has a read-only root filesystem and can only read `data/logs` and write its database under `data/state`; the optional alternate API also has a read-only root filesystem and only reads `data/logs`. The dashboard NGINX service runs unprivileged. Prometheus and Grafana also run with a read-only root filesystem and no Linux capabilities. Prometheus samples and Grafana configuration persist in named Docker volumes. Container base images and monitoring services use explicit upstream version tags; review vendor security updates and upgrade those tags deliberately.

Stop the stack with `docker compose down`. The SQLite database and reports remain in `data/`.

## Run locally without Docker

Python 3.11+ is required. Create the environment and install dependencies once:

```bash
make venv
make run
make exporter
```

To run the API locally, install its dependencies and start it from the repository root:

Use the same owner-only `.env` setup shown in the Docker Compose section first.

```bash
.venv/bin/pip install -r webapi/requirements.txt
WEBAPI_DB_PATH="$PWD/data/state/securewatch.db" \
WEBAPI_LOGS_DIR="$PWD/data/logs" \
WEBAPI_API_KEY="$(sed -n 's/^WEBAPI_API_KEY=//p' .env)" \
.venv/bin/uvicorn webapi.main:app --host 127.0.0.1 --port 8000
```

For dashboard development, use Node.js 20 or newer:

```bash
cd frontend
npm ci
WEBAPI_API_KEY="$(sed -n 's/^WEBAPI_API_KEY=//p' ../.env)" npm run dev
```

The Vite development server runs at <http://127.0.0.1:5173> and adds the API key server-side when proxying requests to port 8000; the key is not included in browser JavaScript.

## Tests and CI

Create the local environment once, then run the deterministic unit tests whenever you change the code:

```bash
make venv
make test
```

These tests use temporary logs, reports, and databases. They do not run a scan against the host. The GitHub Actions workflow also checks Python lint and formatting, validates the Compose configuration, and builds the dashboard.

To run the actual host scan manually, use `make run`; it reads system state and writes generated files under `data/`.

## Releases

Release versions use semantic version tags. Use a suffix for pre-releases, for example `v0.2.0-alpha.1` or `v0.2.0-rc.1`; use `v0.2.0` for a stable release.

Pushing a `v*` tag runs the release workflow. It validates the version and creates a GitHub draft with generated release notes. Tags containing a suffix are marked as pre-releases. Review and publish the draft from the GitHub Releases page.

## Project layout

- `scripts/securewatch.sh` — runs checks, aggregates events, and generates reports.
- `modules/` — individual Linux checks.
- `python/log_parser.py` — parses authentication logs.
- `python/report_generator.py` — creates the HTML report.
- `python/exporters/securewatch_exporter.py` — publishes Prometheus metrics.
- `webapi/` — FastAPI service, SQLite helpers, and report ingestion.
- `backend/` — alternate file-backed API; it uses the same API key and has CORS disabled unless explicit origins are configured.
- `frontend/` — React dashboard and Nginx configuration.
- `dashboards/grafana/` — starter Grafana dashboard.
- `systemd/` — optional scheduled scan and exporter units.

## Security notes

The Compose stack binds its host ports to loopback. Both API implementations require `WEBAPI_API_KEY` for data routes and refuse to start unless it is 64 lowercase hexadecimal characters. The setup command creates the key in an owner-only `.env`, and the file is ignored by Git. The dashboard proxy adds the key server-side so it is not shipped to the browser. The alternate `backend/` service does not enable CORS unless you set a specific comma-separated `SECUREWATCH_CORS_ORIGINS` allowlist. Reports can contain usernames, IP addresses, and other host details. For remote access, put the dashboard behind a TLS-enabled, authenticated reverse proxy and keep the API and monitoring ports private. Review checks and thresholds for your systems before relying on the results.
