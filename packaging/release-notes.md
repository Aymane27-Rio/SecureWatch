## SecureWatch @VERSION@

This stable release makes SecureWatch available as a native Linux package for Debian-family systems and Fedora. The installable package provides the local audit CLI; the Docker Compose dashboard remains optional.

### Install

- Debian or Ubuntu: `sudo apt install ./securewatch_@VERSION@_all.deb`
- Fedora: `sudo dnf install ./securewatch-@VERSION@-1.noarch.rpm`

### Run

Run a full host scan with `sudo securewatch scan`. Render the latest scan as HTML with `sudo securewatch report`. Use `securewatch --help` for command options.

Reports and scan state are stored under `/var/lib/securewatch` with owner-only permissions. The hourly systemd timer is optional and can be enabled with `sudo systemctl enable --now securewatch.timer`. Installing the package does not enable the timer or start a scan.

The packages recommend AIDE, rkhunter, and related utilities for optional checks. Missing optional tools are reported in scan output. SecureWatch reports findings; it does not automatically change firewall rules, install updates, or remediate the host.

SHA256 checksums for the downloadable packages are included in `SHA256SUMS`.
