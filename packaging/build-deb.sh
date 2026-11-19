#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 VERSION OUTPUT_DIRECTORY" >&2
  exit 2
fi

version="$1"
output_dir="$2"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$root/packaging/source-date-epoch.sh"
securewatch_set_source_date_epoch "$root"
if [[ "$version" == *-* ]]; then
  deb_version="${version%%-*}~${version#*-}"
else
  deb_version="$version"
fi
work_dir="$(mktemp -d)"
trap 'rm -rf -- "$work_dir"' EXIT

mkdir -p "$output_dir"
staging_root="$work_dir/root"
bash "$root/packaging/stage-package.sh" "$version" "$staging_root"

mkdir -p "$staging_root/DEBIAN"
cat > "$staging_root/DEBIAN/control" <<EOF
Package: securewatch
Version: $deb_version
Section: admin
Priority: optional
Architecture: all
Depends: bash, coreutils, curl, gawk, hostname, iproute2, jq, python3 (>= 3.11), util-linux
Recommends: aide, inotify-tools, lsof, net-tools, nmap, rkhunter
Maintainer: SecureWatch contributors
Description: Local Linux security audit and reporting tool
 SecureWatch runs host checks, records structured security events, and
 generates private JSON and HTML reports. The web dashboard is optional.
EOF
printf '%s\n' '/etc/securewatch/securewatch.conf' > "$staging_root/DEBIAN/conffiles"
cat > "$staging_root/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi
exit 0
EOF
cat > "$staging_root/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi
exit 0
EOF
cat > "$staging_root/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = remove ] && command -v systemctl >/dev/null 2>&1; then
  systemctl disable --now securewatch.timer securewatch.service >/dev/null 2>&1 || true
fi
exit 0
EOF
chmod 0755 "$staging_root/DEBIAN/postinst" "$staging_root/DEBIAN/prerm" \
  "$staging_root/DEBIAN/postrm"
find "$staging_root" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +

dpkg-deb --build --root-owner-group --uniform-compression \
  "$staging_root" "$work_dir/securewatch_${deb_version}_all.deb"
mv -f -- "$work_dir/securewatch_${deb_version}_all.deb" \
  "$output_dir/securewatch_${deb_version}_all.deb"
