#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 EXPECTED_VERSION" >&2
  exit 2
fi

expected_version="$1"
securewatch --version | grep -Fx "securewatch $expected_version"
securewatch --help >/dev/null
test -x /usr/bin/securewatch
test -r /etc/securewatch/securewatch.conf
test -r /usr/lib/systemd/system/securewatch.service
test -r /usr/lib/systemd/system/securewatch.timer
test "$(stat -c '%a' /var/lib/securewatch)" = 700
test "$(stat -c '%a' /var/lib/securewatch/logs)" = 700
test "$(stat -c '%a' /var/lib/securewatch/state)" = 700

securewatch integrity init --path /etc/hostname
securewatch integrity verify --strict

securewatch scan
latest_events="$(find /var/lib/securewatch/logs -maxdepth 1 -type f -name 'events_*.json' -printf '%T@ %p\n' | sort -nr | head -n1 | cut -d ' ' -f2-)"
test -n "$latest_events"
python3 -c 'import json,sys; events=json.load(open(sys.argv[1], encoding="utf-8")); assert isinstance(events, list); assert any(event.get("category") == "integrity" and event.get("severity") == 0 for event in events if isinstance(event, dict)), "scan did not verify the initialized integrity baseline"' "$latest_events"
securewatch report --input "$latest_events"
test -s "/var/lib/securewatch/reports/report_$(basename "$latest_events" .json).html"
