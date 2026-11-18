#!/usr/bin/env bash
set -euo pipefail

if command -v apt >/dev/null 2>&1; then
  sudo apt update
  # Base utilities
  sudo apt install -y jq curl lsof net-tools inotify-tools util-linux
  # Security tools
  sudo apt install -y rkhunter aide nmap
  sudo apt install -y python3 python3-venv python3-pip
  # Optional Ubuntu-friendly firewall (Kali may use nftables directly).
  sudo apt install -y ufw || true

  echo "Done. Consider initializing AIDE: sudo aideinit && sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db"
elif command -v dnf >/dev/null 2>&1 || command -v dnf5 >/dev/null 2>&1; then
  dnf_command=dnf
  if ! command -v "$dnf_command" >/dev/null 2>&1; then
    dnf_command=dnf5
  fi
  # Fedora package names match the command names used by SecureWatch modules.
  sudo "$dnf_command" install -y jq curl lsof net-tools inotify-tools util-linux hostname
  sudo "$dnf_command" install -y rkhunter aide nmap
  sudo "$dnf_command" install -y python3 python3-pip
  # Optional firewall service; installing it does not enable or start it.
  sudo "$dnf_command" install -y firewalld || true

  echo "Done. Initialize AIDE using Fedora's AIDE setup instructions before relying on integrity scans."
else
  echo "This installer supports apt-based systems (Debian/Ubuntu/Kali) and dnf-based systems (Fedora)." >&2
  exit 1
fi
