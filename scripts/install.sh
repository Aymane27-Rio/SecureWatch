#!/usr/bin/env bash
set -euo pipefail

OS_RELEASE_FILE="${SECUREWATCH_OS_RELEASE_FILE:-/etc/os-release}"
os_id=""
os_like=""

# Parse only the ID fields we need. Do not source os-release as shell code.
if [[ -r "$OS_RELEASE_FILE" ]]; then
  while IFS='=' read -r key value; do
    case "$key" in
      ID|ID_LIKE)
        value=${value%\"}
        value=${value#\"}
        value=${value%\'}
        value=${value#\'}
        if [[ ! "$value" =~ ^[[:alnum:]_.-]*([[:space:]][[:alnum:]_.-]+)*$ ]]; then
          continue
        fi
        if [[ "$key" == ID ]]; then
          os_id="$value"
        else
          os_like="$value"
        fi
        ;;
    esac
  done < "$OS_RELEASE_FILE"
fi

package_manager=""
read -r -a distro_candidates <<< "$os_id $os_like"
for distro in "${distro_candidates[@]}"; do
  case "$distro" in
    debian|ubuntu|kali|linuxmint|pop|elementary|zorin|raspbian)
      package_manager=apt
      break
      ;;
    fedora|rhel|centos|rocky|almalinux|ol)
      package_manager=dnf
      break
      ;;
    opensuse|opensuse-leap|opensuse-tumbleweed|suse|sles)
      package_manager=zypper
      break
      ;;
    arch|archarm|manjaro|endeavouros)
      package_manager=pacman
      break
      ;;
  esac
done

if [[ -z "$package_manager" ]]; then
  printf 'Unsupported Linux distribution (ID=%s ID_LIKE=%s). Supported source installers: Debian/Ubuntu/Kali, Fedora/RHEL-family, openSUSE, and Arch-family.\n' \
    "${os_id:-unknown}" "${os_like:-unknown}" >&2
  exit 1
fi

case "$package_manager" in
  apt)
    package_command=(apt-get)
    command -v apt-get >/dev/null 2>&1 || {
      echo "APT was selected from $OS_RELEASE_FILE, but apt-get is not installed." >&2
      exit 1
    }
    ;;
  dnf)
    if command -v dnf5 >/dev/null 2>&1; then
      package_command=(dnf5)
    elif command -v dnf >/dev/null 2>&1; then
      package_command=(dnf)
    else
      echo "DNF was selected from $OS_RELEASE_FILE, but neither dnf nor dnf5 is installed." >&2
      exit 1
    fi
    ;;
  zypper)
    package_command=(zypper)
    command -v zypper >/dev/null 2>&1 || {
      echo "Zypper was selected from $OS_RELEASE_FILE, but zypper is not installed." >&2
      exit 1
    }
    ;;
  pacman)
    package_command=(pacman)
    command -v pacman >/dev/null 2>&1 || {
      echo "Pacman was selected from $OS_RELEASE_FILE, but pacman is not installed." >&2
      exit 1
    }
    ;;
esac

run_privileged() {
  if [[ "$EUID" -eq 0 ]]; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  else
    echo "Root privileges are required; run this installer with sudo or as root." >&2
    return 1
  fi
}

install_packages() {
  case "$package_manager" in
    apt)
      run_privileged "${package_command[@]}" install -y --no-install-recommends "$@"
      ;;
    dnf)
      run_privileged "${package_command[@]}" install -y "$@"
      ;;
    zypper)
      run_privileged "${package_command[@]}" --non-interactive install --no-recommends "$@"
      ;;
    pacman)
      # Do not run a partial system upgrade. Keep Arch systems updated with pacman -Syu.
      run_privileged "${package_command[@]}" -S --needed --noconfirm "$@"
      ;;
  esac
}

install_optional() {
  local package="$1"
  if ! install_packages "$package"; then
    printf 'Warning: optional package %s could not be installed; SecureWatch will report that check as unavailable.\n' \
      "$package" >&2
  fi
}

case "$package_manager" in
  apt)
    run_privileged apt-get update
    install_packages jq curl lsof net-tools inotify-tools util-linux hostname \
      python3 python3-venv python3-pip
    ;;
  dnf)
    install_packages jq curl lsof net-tools inotify-tools util-linux hostname \
      python3 python3-pip
    ;;
  zypper)
    install_packages jq curl lsof net-tools inotify-tools util-linux hostname \
      python3 python3-pip
    ;;
  pacman)
    install_packages jq curl lsof net-tools inotify-tools util-linux inetutils \
      python python-pip
    ;;
esac

# These scanners are optional and have uneven repository coverage across distros.
optional_packages=(aide rkhunter nmap)
if [[ "$package_manager" == pacman ]]; then
  optional_packages+=(pacman-contrib)
fi
for optional_package in "${optional_packages[@]}"; do
  install_optional "$optional_package"
done

# Installing a firewall implementation does not enable it; keep this best-effort.
case "$package_manager" in
  apt|pacman) install_optional ufw ;;
  dnf|zypper) install_optional firewalld ;;
esac

echo "Done. Initialize AIDE using your distribution's AIDE setup instructions before relying on integrity scans."
