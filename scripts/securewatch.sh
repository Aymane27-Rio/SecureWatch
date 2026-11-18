#!/usr/bin/env bash
set -euo pipefail
umask 077

HERE="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
ROOT="$( dirname "$HERE" )"

# Load config
source "$ROOT/config/securewatch.conf"

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

# Temporary NDJSON file for this run
events_file="$run_dir/events.ndjson"

# Run modules (each module writes NDJSON entries or echoes JSON we capture)
echo "[*] Running modules..."

bash "$ROOT/modules/audit_users.sh"   2>/dev/null >> "$events_file" || true
bash "$ROOT/modules/check_ports.sh"   2>/dev/null >> "$events_file" || true
bash "$ROOT/modules/firewall_status.sh" 2>/dev/null >> "$events_file" || true
bash "$ROOT/modules/check_updates.sh" 2>/dev/null >> "$events_file" || true
bash "$ROOT/modules/rkhunter_run.sh"  2>/dev/null >> "$events_file" || true
bash "$ROOT/modules/aide_check.sh"    2>/dev/null >> "$events_file" || true
bash "$ROOT/modules/file_integrity.sh" 2>/dev/null >> "$events_file" || true

# paarse system logs for suspicious activity (SSH brute force and sudo anomalies)
if command -v python3 >/dev/null 2>&1; then
  python3 "$ROOT/python/log_parser.py" --threshold "${SSH_FAILED_THRESHOLD}" --out "$run_dir/log_anomalies.ndjson" || true
  [ -s "$run_dir/log_anomalies.ndjson" ] && cat "$run_dir/log_anomalies.ndjson" >> "$events_file"
fi

# aggregate → stable JSON (array)
out_json="$LOG_DIR/events_${run_id}.json"
if command -v jq >/dev/null 2>&1; then
  jq -s '[.[]]' "$events_file" > "$out_json"
else
  # Fallback: wrap lines in array
  echo "[" > "$out_json"; paste -sd, "$events_file" >> "$out_json"; echo "]" >> "$out_json"
fi
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

# Alert on critical findings (severity >= 3)
critical_count=$(jq '[.[] | select(.severity >= 3)] | length' "$out_json" 2>/dev/null || echo "0")
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
