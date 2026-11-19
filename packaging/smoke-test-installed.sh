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
python3 - "$latest_events" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as report:
    events = json.load(report)
assert isinstance(events, list)
valid_events = [event for event in events if isinstance(event, dict)]
assert any(
    event.get("category") == "integrity" and event.get("severity") == 0
    for event in valid_events
), "scan did not verify the initialized integrity baseline"
assert any(
    event.get("category") == "accounts"
    and event.get("severity") == 0
    and event.get("summary") == "Only the root account uses UID 0"
    for event in valid_events
), "scan did not run the account audit cleanly"
assert any(event.get("category") == "ssh" for event in valid_events), (
    "scan did not run the SSH audit"
)
PY
securewatch report --input "$latest_events"
test -s "/var/lib/securewatch/reports/report_$(basename "$latest_events" .json).html"
