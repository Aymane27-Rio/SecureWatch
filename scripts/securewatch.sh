#!/usr/bin/env bash
set -euo pipefail
umask 077

HERE="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
ROOT="$( dirname "$HERE" )"
cd "$ROOT"

# Load config
CONFIG_FILE="${SECUREWATCH_CONFIG:-$ROOT/config/securewatch.conf}"
if [[ ! -r "$CONFIG_FILE" ]]; then
  echo "SecureWatch configuration is not readable: $CONFIG_FILE" >&2
  exit 1
fi
source "$CONFIG_FILE"

mkdir -p "$LOG_DIR" "$REPORT_DIR" "$STATE_DIR"

if ! command -v flock >/dev/null 2>&1; then
  echo "flock is required for scan locking; install util-linux." >&2
  exit 1
fi
exec 9>"$STATE_DIR/scan.lock"
if ! flock -n 9; then
  echo "A SecureWatch scan is already running." >&2
  exit 75
fi
if [[ "$EUID" -eq 0 ]]; then
  chown --reference="$STATE_DIR" -- "$STATE_DIR/scan.lock"
fi

timestamp="$(date +%Y%m%d_%H%M%S)"
run_dir="$(mktemp -d "$STATE_DIR/run_${timestamp}.XXXXXX")"
run_id="${run_dir##*/run_}"

out_json="$LOG_DIR/events_${run_id}.json"
echo "[*] Running modules..."
python3 "$ROOT/python/scan_runner.py" \
  --root "$ROOT" \
  --work-dir "$run_dir" \
  --output "$out_json" \
  --ssh-threshold "$SSH_FAILED_THRESHOLD"
echo "[*] Wrote events: $out_json"
if [[ "$EUID" -eq 0 && -f "$out_json" ]]; then
  chown --reference="$LOG_DIR" -- "$out_json"
fi

# render HTML report
if command -v python3 >/dev/null 2>&1; then
  report_file="$REPORT_DIR/report_${run_id}.html"
  python3 "$ROOT/python/report_generator.py" --input "$out_json" --out "$report_file" || true
  if [[ "$EUID" -eq 0 && -f "$report_file" ]]; then
    chown --reference="$REPORT_DIR" -- "$report_file"
  fi
fi

# Report incomplete checks to the interactive operator as well as in the report.
audit_failure_count=$(python3 - "$out_json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as report:
    events = json.load(report)
print(
    sum(
        1
        for event in events
        if isinstance(event, dict)
        and event.get("category") == "audit"
        and str(event.get("summary", "")).startswith("Audit check failed:")
    )
)
PY
)
if [ "$audit_failure_count" -gt 0 ]; then
  echo "[!] Audit checks failed: $audit_failure_count; review $out_json"
fi

# Alert on critical findings (severity >= 3)
critical_count=$(python3 - "$out_json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as report:
    events = json.load(report)
print(
    sum(
        1
        for event in events
        if isinstance(event, dict)
        and isinstance(event.get("severity"), int)
        and event["severity"] >= 3
    )
)
PY
)
if [ "$critical_count" -gt 0 ]; then
  echo "[!] Critical findings: $critical_count"
  bash "$ROOT/scripts/notify.sh" "$out_json" "$critical_count" || true
fi
# Notifying the webapi

if [ -n "${WEBAPI_INGEST_URL:-}" ] && [ -n "${WEBAPI_API_KEY:-}" ]; then
  curl --fail --silent --show-error --connect-timeout 5 --max-time 15 \
    -X POST -H "X-API-Key: ${WEBAPI_API_KEY}" "${WEBAPI_INGEST_URL}" || true
fi

echo "[*] SecureWatch run complete."
