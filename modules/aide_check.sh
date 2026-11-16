#!/usr/bin/env bash
set -euo pipefail
HOST=$(hostname)
TS=$(date -Iseconds)
if command -v aide >/dev/null 2>&1; then
  tmp_dir="$(mktemp -d /tmp/securewatch-aide.XXXXXX)"
  trap 'rm -rf -- "$tmp_dir"' EXIT
  aide_output="$tmp_dir/output"
  if sudo aide --check >"$aide_output" 2>&1; then
    check_status=0
  else
    check_status=$?
  fi

  if grep -q "AIDE found differences" "$aide_output"; then
    echo "{\"ts\":\"$TS\",\"host\":\"$HOST\",\"category\":\"integrity\",\"severity\":3,\"summary\":\"AIDE found differences\",\"data\":{}}"
  elif [ "$check_status" -ne 0 ]; then
    echo "{\"ts\":\"$TS\",\"host\":\"$HOST\",\"category\":\"integrity\",\"severity\":3,\"summary\":\"AIDE check failed\",\"data\":{\"exit_code\":$check_status}}"
  else
    echo "{\"ts\":\"$TS\",\"host\":\"$HOST\",\"category\":\"integrity\",\"severity\":0,\"summary\":\"AIDE no differences\",\"data\":{}}"
  fi
else
  echo "{\"ts\":\"$TS\",\"host\":\"$HOST\",\"category\":\"integrity\",\"severity\":1,\"summary\":\"AIDE not installed\",\"data\":{}}"
fi
