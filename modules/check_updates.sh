#!/usr/bin/env bash
set -euo pipefail
HOST=$(hostname)
TS=$(date -Iseconds)

if command -v apt >/dev/null 2>&1; then
  updates=$(LC_ALL=C apt list --upgradable 2>/dev/null | awk 'NR > 1 {count++} END {print count+0}')
  manager=apt
elif command -v dnf5 >/dev/null 2>&1; then
  dnf_command=dnf5
  manager=dnf5
elif command -v dnf >/dev/null 2>&1; then
  dnf_command=dnf
  dnf_version=$(LC_ALL=C dnf --version 2>/dev/null || true)
  dnf_version_line=${dnf_version%%$'\n'*}
  if [[ "$dnf_version_line" == 5.* ]]; then
    manager=dnf5
  else
    manager=dnf
  fi
else
  echo "{\"ts\":\"$TS\",\"host\":\"$HOST\",\"category\":\"packages\",\"severity\":1,\"summary\":\"No supported package manager found\",\"data\":{}}"
  exit 0
fi

if [ "$manager" != apt ]; then
  if [ "$manager" = dnf5 ]; then
    if updates_output=$(LC_ALL=C "$dnf_command" check-upgrade --json 2>/dev/null); then
      update_status=0
    else
      update_status=$?
    fi
  else
    if updates_output=$(LC_ALL=C "$dnf_command" check-update 2>&1); then
      update_status=0
    else
      update_status=$?
    fi
  fi

  case "$update_status" in
    0)
      updates=0
      ;;
    100)
      if [ "$manager" = dnf5 ]; then
        updates=$(printf '%s' "$updates_output" | python3 -c 'import json,sys; data=json.load(sys.stdin); print(sum(len(section) for section in data.values() if isinstance(section, list)))' 2>/dev/null) || updates=0
      else
        updates=$(printf '%s\n' "$updates_output" | awk '$1 ~ /\.[[:alnum:]_]+$/ && NF >= 3 {count++} END {print count+0}')
      fi
      # Exit status 100 guarantees at least one update even if output formatting changes.
      if [ "$updates" -eq 0 ]; then updates=1; fi
      ;;
    *)
      echo "{\"ts\":\"$TS\",\"host\":\"$HOST\",\"category\":\"packages\",\"severity\":2,\"summary\":\"Package update check failed\",\"data\":{\"manager\":\"$manager\",\"exit_code\":$update_status}}"
      exit 0
      ;;
  esac
fi

severity=0
if [ "$updates" -gt 0 ]; then severity=1; fi
echo "{\"ts\":\"$TS\",\"host\":\"$HOST\",\"category\":\"packages\",\"severity\":$severity,\"summary\":\"Upgradable packages: $updates\",\"data\":{\"count\":$updates,\"manager\":\"$manager\"}}"
