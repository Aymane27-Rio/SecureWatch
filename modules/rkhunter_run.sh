#!/usr/bin/env bash
set -euo pipefail
HOST=$(hostname)
TS=$(date -Iseconds)
if command -v rkhunter >/dev/null 2>&1; then
  if out="$(sudo rkhunter --check --sk --nocolors --quiet 2>&1)"; then
    check_status=0
  else
    check_status=$?
  fi
  warnings="$(printf '%s\n' "$out" | grep -c "Warning:" || true)"

  if [ "$warnings" -gt 0 ]; then
    echo "{\"ts\":\"$TS\",\"host\":\"$HOST\",\"category\":\"malware\",\"severity\":2,\"summary\":\"rkhunter warnings: $warnings\",\"data\":{\"warnings\":$warnings}}"
  elif [ "$check_status" -ne 0 ]; then
    echo "{\"ts\":\"$TS\",\"host\":\"$HOST\",\"category\":\"malware\",\"severity\":3,\"summary\":\"rkhunter check failed\",\"data\":{\"exit_code\":$check_status}}"
  else
    echo "{\"ts\":\"$TS\",\"host\":\"$HOST\",\"category\":\"malware\",\"severity\":0,\"summary\":\"rkhunter warnings: 0\",\"data\":{\"warnings\":0}}"
  fi
else
  echo "{\"ts\":\"$TS\",\"host\":\"$HOST\",\"category\":\"malware\",\"severity\":1,\"summary\":\"rkhunter not installed\",\"data\":{}}"
fi
