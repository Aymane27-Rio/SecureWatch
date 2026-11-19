#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 VERSION STAGING_ROOT" >&2
  exit 2
fi

version="$1"
staging_root="$2"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$root/packaging/source-date-epoch.sh"
securewatch_set_source_date_epoch "$root"

if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "Invalid version: $version" >&2
  exit 2
fi

mkdir -p \
  "$staging_root/usr/lib/securewatch/bin" \
  "$staging_root/usr/lib/securewatch/scripts" \
  "$staging_root/usr/lib/securewatch/modules" \
  "$staging_root/usr/lib/securewatch/python" \
  "$staging_root/usr/share/doc/securewatch" \
  "$staging_root/usr/bin" \
  "$staging_root/usr/lib/systemd/system" \
  "$staging_root/etc/securewatch" \
  "$staging_root/var/lib/securewatch/logs" \
  "$staging_root/var/lib/securewatch/reports" \
  "$staging_root/var/lib/securewatch/state"

install -m 0755 "$root/bin/securewatch" "$staging_root/usr/lib/securewatch/bin/securewatch"
printf '%s\n' "$version" > "$staging_root/usr/lib/securewatch/VERSION"
chmod 0644 "$staging_root/usr/lib/securewatch/VERSION"
install -m 0755 "$root/scripts/securewatch.sh" "$root/scripts/notify.sh" \
  "$staging_root/usr/lib/securewatch/scripts/"
install -m 0755 "$root/modules/"*.sh "$staging_root/usr/lib/securewatch/modules/"
install -m 0644 "$root/python/log_parser.py" "$root/python/report_generator.py" \
  "$root/python/scan_runner.py" "$root/python/file_integrity.py" \
  "$root/python/audit_users.py" "$root/python/ssh_hardening.py" \
  "$root/python/doctor.py" \
  "$staging_root/usr/lib/securewatch/python/"
install -m 0644 "$root/LICENSE" "$staging_root/usr/share/doc/securewatch/LICENSE"
install -m 0644 "$root/README.md" "$staging_root/usr/share/doc/securewatch/README.md"
install -m 0644 "$root/packaging/securewatch.conf" \
  "$staging_root/etc/securewatch/securewatch.conf"
install -m 0644 "$root/systemd/securewatch.service" "$root/systemd/securewatch.timer" \
  "$staging_root/usr/lib/systemd/system/"
ln -s ../lib/securewatch/bin/securewatch "$staging_root/usr/bin/securewatch"

chmod 0700 \
  "$staging_root/var/lib/securewatch" \
  "$staging_root/var/lib/securewatch/logs" \
  "$staging_root/var/lib/securewatch/reports" \
  "$staging_root/var/lib/securewatch/state"

find "$staging_root" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
