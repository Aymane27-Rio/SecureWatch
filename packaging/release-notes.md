## SecureWatch @VERSION@

This @RELEASE_CHANNEL@ makes SecureWatch available as a native Linux package for Debian-family systems, Fedora, and openSUSE Tumbleweed. The installable package provides the local audit CLI; the Docker Compose dashboard remains optional.

### Highlights

- Cross-distro host checks now cover Alpine, Arch, Debian-family systems, Fedora, and openSUSE Tumbleweed.
- A read-only host preflight and built-in file-integrity baseline help check readiness and detect changes to critical configuration files.
- The dashboard includes scan history, event filters, and expandable event details.

### Install

- Debian, Ubuntu, or Kali: `sudo apt install ./securewatch_@VERSION@_all.deb`
- Fedora: `sudo dnf install ./securewatch-@RPM_VERSION@-@RPM_RELEASE@.noarch.rpm`
- openSUSE Tumbleweed: `sudo zypper install ./securewatch-@RPM_VERSION@-@RPM_RELEASE@.noarch.rpm`

### Run

Run a full host scan with `sudo securewatch scan`. Render the latest scan as HTML with `sudo securewatch report`. Use `securewatch --help` for command options.

Reports and scan state are stored under `/var/lib/securewatch` with owner-only permissions. The hourly systemd timer is optional and can be enabled with `sudo systemctl enable --now securewatch.timer`. Installing the package does not enable the timer or start a scan.

The packages recommend AIDE, rkhunter, and related utilities for optional checks. Missing optional tools are reported in scan output. SecureWatch reports findings; it does not automatically change firewall rules, install updates, or remediate the host.

SHA256 checksums for the downloadable packages are included in `SHA256SUMS`.
