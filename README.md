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
mkdir -p data
printf 'WEBAPI_API_KEY=%s\n' "$(openssl rand -hex 32)" > .env
docker compose up --build -d
```

The stack binds to localhost by default:

- Dashboard: <http://127.0.0.1:3000>
- API: <http://127.0.0.1:8000>
- Prometheus: <http://127.0.0.1:9090>
- Grafana: <http://127.0.0.1:3001>
- Exporter: <http://127.0.0.1:9109/metrics>

Run a scan from the repository root with `make run`. Reports and logs appear under `data/`; the API imports new event files automatically. A few checks use `sudo` for full visibility. To expose the stack on another interface, set `SECUREWATCH_BIND_ADDRESS` in `.env` before starting Compose.

Stop the stack with `docker compose down`. The SQLite database and reports remain in `data/`.

## Run locally without Docker

Python 3.11+ is required. Create the environment and install dependencies once:

```bash
make venv
make run
make exporter
```

To run the API locally, install its dependencies and start it from the repository root:

```bash
.venv/bin/pip install -r webapi/requirements.txt
WEBAPI_DB_PATH="$PWD/data/state/securewatch.db" \
WEBAPI_LOGS_DIR="$PWD/data/logs" \
WEBAPI_API_KEY="$(openssl rand -hex 32)" \
.venv/bin/uvicorn webapi.main:app --host 127.0.0.1 --port 8000
```

For dashboard development, use Node.js 20 or newer:

```bash
cd frontend
npm ci
npm run dev
```

The Vite development server runs at <http://127.0.0.1:5173> and proxies API requests to port 8000.

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
- `frontend/` — React dashboard and Nginx configuration.
- `dashboards/grafana/` — starter Grafana dashboard.
- `systemd/` — optional scheduled scan and exporter units.

## Security notes

The Compose stack binds to localhost by default. API write operations require `WEBAPI_API_KEY`; keep `.env` private. Read endpoints do not require a key, so add an authenticated reverse proxy before exposing the stack beyond localhost. Reports can contain usernames and IP addresses, so handle and share them carefully. Review checks and thresholds for your systems before relying on the results.
