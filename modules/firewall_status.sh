#!/usr/bin/env bash
set -euo pipefail
HOST=$(hostname)
TS=$(date -Iseconds)

report() {
  local severity="$1"
  local summary="$2"
  local data="$3"
  echo "{\"ts\":\"$TS\",\"host\":\"$HOST\",\"category\":\"firewall\",\"severity\":$severity,\"summary\":\"$summary\",\"data\":{$data}}"
}

ufw_status=""
if command -v ufw >/dev/null 2>&1; then
  if ufw_output=$(ufw status 2>/dev/null); then
    ufw_status=$(printf '%s\n' "$ufw_output" | head -n1 | awk '{print $2}')
    if [[ "$ufw_status" == active ]]; then
      report 0 "UFW active" "\"ufw_status\":\"active\""
      exit 0
    fi
    if [[ -z "$ufw_status" ]]; then
      ufw_status=unknown
    fi
  else
    ufw_status=error
  fi
fi

firewalld_status=""
if command -v firewall-cmd >/dev/null 2>&1; then
  if LC_ALL=C firewall-cmd --state >/dev/null 2>&1; then
    report 0 "firewalld active" "\"firewalld_status\":\"running\""
    exit 0
  fi
  firewalld_status=inactive
fi

if command -v nft >/dev/null 2>&1; then
  if nft_output=$(nft list ruleset 2>/dev/null); then
    if [[ -n "$nft_output" ]]; then
      if printf '%s\n' "$nft_output" | grep -Eq 'hook (input|forward|output)([[:space:]]|$)'; then
        report 1 "nftables filter chains detected; review their rules and policies" \
          "\"nftables_status\":\"filter-chains-present\",\"filter_chain_present\":true"
      else
        report 1 "nftables ruleset present; verify that it filters host traffic" \
          "\"nftables_status\":\"rules-present\",\"filter_chain_present\":false"
      fi
    else
      report 2 "nftables ruleset is empty" "\"nftables_status\":\"empty\""
    fi
    exit 0
  else
    nft_status=$?
  fi
  report 2 "nftables ruleset check failed" "\"nftables_status\":\"error\",\"exit_code\":$nft_status"
  exit 0
fi

if [[ "$ufw_status" == error || "$ufw_status" == unknown ]]; then
  report 2 "UFW status check failed" "\"ufw_status\":\"$ufw_status\""
elif [[ -n "$ufw_status" ]]; then
  report 2 "UFW inactive" "\"ufw_status\":\"$ufw_status\""
elif [[ -n "$firewalld_status" ]]; then
  report 2 "firewalld inactive" "\"firewalld_status\":\"inactive\""
else
  report 1 "No supported firewall tool installed" ""
fi
