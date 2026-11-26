# SecureWatch

SecureWatch is a modular Linux security monitoring toolkit. It runs local checks, parses authentication logs, creates JSON and HTML reports, and can display scan data in a web dashboard with Prometheus and Grafana.

## Features

- Local checks for privileged accounts, SSH authentication settings, listening ports, firewall state, package updates, AIDE, and rkhunter.
- A built-in file-integrity baseline that hashes critical configuration files and checks their content, ownership, and permissions.
- Scan failures and malformed check output are recorded in reports and called out in the terminal, so incomplete coverage is visible.
- SSH and sudo anomaly parsing with structured JSON events.
- HTML reports and a FastAPI service that stores reports and events in SQLite.
- React dashboard for scan history, scan-to-scan finding comparison, severity/category filtering, event details, filtered CSV export, and advisory persona-aware guidance for SSH findings, plus a Prometheus exporter and starter Grafana dashboard.
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

Run a scan from the repository root with `make run` or `python3 bin/securewatch scan`. Reports and logs appear under `data/`; the API imports new event files automatically. A few checks use `sudo` for full visibility. The API requires the configured `X-API-Key` for report and event routes, so keep the Compose ports loopback-only. For remote dashboard access, use a host-based reverse proxy with TLS and authentication, targeting `127.0.0.1:3000`; do not publish the API, Prometheus, Grafana, or exporter ports directly.

Both API images and the metrics exporter run as the configured host UID/GID without Linux capabilities. The primary API container has a read-only root filesystem and can only read `data/logs` and write its database under `data/state`; the optional alternate API also has a read-only root filesystem and only reads `data/logs`. The dashboard NGINX service runs unprivileged. Prometheus and Grafana also run with a read-only root filesystem and no Linux capabilities. Prometheus samples and Grafana configuration persist in named Docker volumes. Container base images and monitoring services use explicit upstream version tags; review vendor security updates and upgrade those tags deliberately.

Stop the stack with `docker compose down`. The SQLite database and reports remain in `data/`.

## Run locally without Docker

The source dependency installer supports APK on Alpine, APT on Debian, Ubuntu, Kali, and compatible derivatives; DNF on Fedora and compatible RHEL derivatives; Zypper on openSUSE; and Pacman on Arch-family systems. On minimal Alpine systems, bootstrap Bash and Make first with `doas apk add --no-cache bash make` (or run `apk add --no-cache bash make` as root), then use `make install-deps`. The native packages are currently built for Debian-family systems (`.deb`) and Fedora (`.rpm`); the `.deb` was also smoke-tested on Kali. CI runs a full local audit on Alpine, source setup plus package and firewall checks on openSUSE Tumbleweed and Arch, and package installation smoke tests on Kali, Debian, Ubuntu, and Fedora. On other Linux systems, the source CLI can be run manually if Bash, Python 3.11+, `flock` from util-linux, and the required utilities are available. Optional scanners that are missing or unavailable from a distribution's repositories are reported as unavailable rather than blocking installation. On Arch-family systems, update the system with `sudo pacman -Syu` before installing dependencies; SecureWatch avoids triggering a partial system upgrade.

Update checks cover APK, APT, DNF/DNF5, Zypper, and Pacman through `checkupdates` from `pacman-contrib`. The APK check refreshes repository indexes before counting available upgrades; it never upgrades installed packages. Firewall checks recognize an existing UFW, firewalld, or nftables setup; SecureWatch does not install or enable firewall software. nftables rules are reported for review and are not treated as proof of a safe policy. Install host packages and create the Python environment once:

```bash
make install-deps
make venv
python3 bin/securewatch --help
make run
make exporter
```

The source CLI supports `scan`, `report`, `--help`, and `--version`. `report` renders the latest scan as HTML; pass `--input PATH` or `--output PATH` to select files explicitly. Source runs store private reports under the repository's `data/` directory. The web dashboard remains optional and can still be run with Docker Compose.

Run `securewatch doctor` before a scan to check the Python version, required commands, package-manager commands on `PATH`, optional audit tools, and whether the command has root visibility. It is read-only and does not install packages or contact repositories. Missing optional tools are reported as unavailable checks; the command exits nonzero when Python or a required runtime command is missing. Add `--json` for automation.

The account check treats the expected `root` account as normal and flags additional accounts assigned UID 0. Malformed or unreadable account data is reported as incomplete instead of being treated as a clean result.

When OpenSSH server is installed, scans inspect its effective configuration with `sshd -T -C` for four representative connection contexts: root and a regular account (`nobody`), each from loopback and a reserved external IPv4 address. The audit reads the configured listener ports and checks up to four of them, so `Match LocalPort` rules on nonstandard ports are included. If more than four ports are configured, the report marks the port audit incomplete. This check is read-only and does not open a network connection or modify SSH configuration. The samples do not exhaust every username, source or destination address, IPv6 route, or hostname that may match your rules; review context-specific rules for your environment. Findings identify the sample context and port. Missing OpenSSH is reported as an unavailable optional check.

## File integrity baseline

Initialize the built-in baseline once before relying on file-integrity findings. Use `--strict` when automation should fail on drift or incomplete verification:

```bash
sudo securewatch integrity init
sudo securewatch scan
sudo securewatch integrity verify --strict
```

The default baseline tracks existing files among `/etc/passwd`, `/etc/group`, `/etc/shadow`, `/etc/gshadow`, `/etc/sudoers`, and `/etc/ssh/sshd_config`. To track a custom set instead, pass one or more `--path` options, for example `securewatch integrity init --path /etc/securewatch/securewatch.conf --path /etc/ssh/sshd_config`. An existing baseline is never replaced unless `--force` is supplied; use that only after reviewing the current changes. Scans report a missing baseline as incomplete instead of claiming file integrity is clean. Baselines are stored with owner-only permissions and contain hashes and metadata, not file contents. The baseline is local state and a privileged attacker can replace it, so keep a protected off-host copy if you need tamper evidence against root-level compromise.

## SSH finding guidance

Expand a supported SSH setting finding in the dashboard to see its observed value, suggested value, and evaluated connection context. Choose Standard user, Developer, or Pentester to tailor the advisory next steps. SecureWatch does not apply these changes; review access requirements and validate a proposed SSH change before deploying it.

The dashboard compares each selected report with the next older scan, labeling new and persistent findings and listing resolved findings. Informational events are excluded; changes in severity are counted separately, while observed counts and timestamps do not make an otherwise matching finding appear new.

## Installable packages

SecureWatch packages provide the local audit CLI and optional systemd timer; they do not install or start the web dashboard. Debian-family packages are built with `dpkg-deb`; RPM packages are built with `rpmbuild` and tested on Fedora and openSUSE Tumbleweed:

```bash
make package-deb VERSION=0.4.0 OUTPUT=dist
make package-rpm VERSION=0.4.0 OUTPUT=dist
```

For the stable `v0.4.0` release, install the downloaded asset with your system package manager: `sudo apt install ./securewatch_0.4.0_all.deb` on Debian-family systems, including Kali; `sudo dnf install ./securewatch-0.4.0-1.noarch.rpm` on Fedora; or `sudo zypper install ./securewatch-0.4.0-1.noarch.rpm` on openSUSE Tumbleweed. The Debian package requires Python 3.11 or later. Run `sudo securewatch scan` for a complete host audit. Reports and scan data are stored with owner-only permissions under `/var/lib/securewatch`. The hourly timer is opt-in: enable it with `sudo systemctl enable --now securewatch.timer`. Package upgrades preserve `/etc/securewatch/securewatch.conf` and generated reports. Package removal also leaves generated reports and scan data in place.

The Debian package recommends AIDE, rkhunter, Nmap, and network utilities for optional checks. Fedora's package recommends the equivalent Fedora packages. Missing optional tools are reported in scan output.

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

The unit tests use temporary logs, reports, and databases; they do not scan the development machine. CI builds packages twice to check repeatability and install-tests the Debian package on Debian, Ubuntu, and Kali and the RPM on Fedora and openSUSE Tumbleweed, including integrity-baseline setup, a scan, and an HTML report in each environment.

To run the actual host scan manually, use `make run`; it reads system state and writes generated files under `data/`.

## Feedback and bug reports

Use the [GitHub Issues page](https://github.com/Aymane27-Rio/SecureWatch/issues/new/choose) and choose Bug report, Feature request, or General feedback. Include the SecureWatch version, Linux distribution, and installation method when relevant. Reports can contain hostnames, usernames, IP addresses, or configuration details, so share only short, redacted excerpts rather than full scan reports or credentials.

## Releases

Release versions use semantic version tags. Use a suffix for pre-releases, for example `v0.2.0-alpha.1` or `v0.2.0-rc.1`; use `v0.2.0` for a stable release.

Pushing a `v*` tag runs the release workflow. The tag must match `VERSION`; the workflow rebuilds and install-tests the Debian package and tests the RPM on Fedora and openSUSE Tumbleweed, generates checksums, and creates a GitHub draft with version-correct install instructions and release notes. Tags containing a suffix are marked as pre-releases; a tag such as `v0.4.0` creates a stable release draft. Review the draft and publish it from the GitHub Releases page.

## Project layout

- `bin/securewatch` — user-facing CLI for scans and HTML reports.
- `VERSION` — version embedded in package builds and checked against release tags.
- `scripts/securewatch.sh` — runs checks, aggregates events, and generates reports.
- `packaging/` — Debian/RPM build definitions and installed-package smoke checks.
- `modules/` — individual Linux checks.
- `python/log_parser.py` — parses authentication logs.
- `python/doctor.py` — checks host readiness and available audit checks.
- `python/report_generator.py` — creates the HTML report.
- `python/exporters/securewatch_exporter.py` — publishes Prometheus metrics.
- `webapi/` — FastAPI service, SQLite helpers, and report ingestion.
- `backend/` — alternate file-backed API; it uses the same API key and has CORS disabled unless explicit origins are configured.
- `frontend/` — React dashboard and Nginx configuration.
- `dashboards/grafana/` — starter Grafana dashboard.
- `systemd/` — optional scheduled scan and exporter units.

## Security notes

The Compose stack binds its host ports to loopback. Both API implementations require `WEBAPI_API_KEY` for data routes and refuse to start unless it is 64 lowercase hexadecimal characters. The setup command creates the key in an owner-only `.env`, and the file is ignored by Git. The dashboard proxy adds the key server-side so it is not shipped to the browser. Both APIs and the metrics exporter share a report reader that rejects symlinks, caps reports at 10 MiB and 100,000 events by default, and validates event fields; the primary API commits each report atomically, and the exporter maps unknown categories to `other` to limit metric cardinality. Set `WEBAPI_MAX_REPORT_BYTES` to a positive byte count if your generated reports need a different byte limit. The alternate `backend/` service does not enable CORS unless you set a specific comma-separated `SECUREWATCH_CORS_ORIGINS` allowlist. Reports can contain usernames, IP addresses, and other host details. File-integrity baselines are owner-only but remain writable by the same privileged account that runs SecureWatch; retain a protected external copy for tamper evidence against root-level compromise. For remote access, put the dashboard behind a TLS-enabled, authenticated reverse proxy and keep the API and monitoring ports private. Review checks and thresholds for your systems before relying on the results.
