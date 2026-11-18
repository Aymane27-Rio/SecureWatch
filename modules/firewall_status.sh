#!/usr/bin/env bash
set -euo pipefail
HOST=$(hostname)
TS=$(date -Iseconds)
if command -v ufw >/dev/null 2>&1; then
  st=$(ufw status | head -n1 | awk '{print $2}')
  if [ "$st" = "active" ]; then
    sev=0; summary="UFW active"
  else
    sev=2; summary="UFW inactive"
  fi
  echo "{\"ts\":\"$TS\",\"host\":\"$HOST\",\"category\":\"firewall\",\"severity\":$sev,\"summary\":\"$summary\",\"data\":{\"ufw_status\":\"$st\"}}"
elif command -v firewall-cmd >/dev/null 2>&1; then
  if LC_ALL=C firewall-cmd --state >/dev/null 2>&1; then
    sev=0; summary="firewalld active"; st="running"
  else
    sev=2; summary="firewalld inactive"; st="inactive"
  fi
  echo "{\"ts\":\"$TS\",\"host\":\"$HOST\",\"category\":\"firewall\",\"severity\":$sev,\"summary\":\"$summary\",\"data\":{\"firewalld_status\":\"$st\"}}"
else
  echo "{\"ts\":\"$TS\",\"host\":\"$HOST\",\"category\":\"firewall\",\"severity\":1,\"summary\":\"No supported firewall tool installed\",\"data\":{}}"
fi
