#!/usr/bin/env python3
"""Check whether this host has the runtime needed for SecureWatch scans."""

import argparse
import datetime
import json
import os
import re
import shutil
import socket
import sys
from pathlib import Path

from ssh_hardening import locate_sshd

MAX_OS_RELEASE_BYTES = 64 * 1024
OS_RELEASE_TOKEN = re.compile(r"^[A-Za-z0-9_.-]+$")
REQUIRED_COMMANDS = ("bash", "flock", "python3")
PACKAGE_MANAGERS = (
    ("apt", "apt"),
    ("apt", "apt-get"),
    ("dnf", "dnf5"),
    ("dnf", "dnf"),
    ("zypper", "zypper"),
    ("pacman", "pacman"),
    ("apk", "apk"),
)
OPTIONAL_CHECKS = (
    ("Listening port audit", ("ss", "netstat")),
    ("Firewall status audit", ("ufw", "firewall-cmd", "nft")),
    ("SSH server configuration audit", ("sshd",)),
    ("AIDE database audit", ("aide",)),
    ("Rootkit Hunter scan", ("rkhunter",)),
)


def _parse_os_release(path):
    fields = {}
    try:
        with Path(path).open("rb") as source:
            content = source.read(MAX_OS_RELEASE_BYTES + 1)
    except OSError as error:
        return fields, f"could not read os-release: {error.strerror}"
    if len(content) > MAX_OS_RELEASE_BYTES:
        return fields, "os-release exceeds the size limit"

    for line in content.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key not in {"ID", "ID_LIKE", "PRETTY_NAME"}:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            quote = value[0]
            value = value[1:-1]
            if quote == '"':
                value = value.replace('\\"', '"').replace("\\\\", "\\")
        fields[key] = value

    distro_id = fields.get("ID", "").lower()
    if not OS_RELEASE_TOKEN.fullmatch(distro_id):
        distro_id = ""
    fields["ID"] = distro_id
    id_like = fields.get("ID_LIKE", "").lower().split()
    fields["ID_LIKE"] = " ".join(
        token for token in id_like if OS_RELEASE_TOKEN.fullmatch(token)
    )
    pretty_name = fields.get("PRETTY_NAME", "")
    fields["PRETTY_NAME"] = "".join(char for char in pretty_name if char.isprintable())[
        :160
    ]
    return fields, None


def inspect_system(
    os_release_path="/etc/os-release",
    command_lookup=None,
    ssh_server_lookup=None,
    python_version=None,
    is_root=None,
    hostname=None,
):
    """Return preflight results without modifying the host or accessing network."""
    command_lookup = command_lookup or shutil.which
    ssh_server_lookup = ssh_server_lookup or locate_sshd
    python_version = python_version or sys.version_info[:3]
    is_root = os.geteuid() == 0 if is_root is None else is_root
    hostname = socket.gethostname() if hostname is None else hostname

    os_fields, os_release_error = _parse_os_release(os_release_path)
    required_commands = {
        command: command_lookup(command) is not None for command in REQUIRED_COMMANDS
    }
    python_supported = tuple(python_version[:2]) >= (3, 11)

    package_manager_commands = []
    for _manager, command in PACKAGE_MANAGERS:
        if command_lookup(command) and command not in package_manager_commands:
            package_manager_commands.append(command)

    optional_checks = {}
    for label, commands in OPTIONAL_CHECKS:
        if label == "SSH server configuration audit":
            found = ["sshd"] if ssh_server_lookup() else []
        else:
            found = [command for command in commands if command_lookup(command)]
        optional_checks[label] = {"available": bool(found), "commands": found}

    update_manager = next(
        (
            command
            for command in ("apt", "dnf5", "dnf", "zypper", "pacman", "apk")
            if command_lookup(command)
        ),
        None,
    )
    update_commands = [update_manager] if update_manager else []
    if update_manager == "pacman" and command_lookup("checkupdates"):
        update_commands.append("checkupdates")
    package_update_available = bool(update_manager) and (
        update_manager != "pacman" or "checkupdates" in update_commands
    )
    optional_checks["Package update audit"] = {
        "available": package_update_available,
        "commands": update_commands,
    }

    warnings = []
    if os_release_error:
        warnings.append(os_release_error)
    if not os_fields.get("ID"):
        warnings.append("Linux distribution identity could not be determined")
    if not package_manager_commands:
        warnings.append("No supported package manager command was found")
    if not python_supported:
        warnings.append("Python 3.11 or newer is required")
    missing_commands = [name for name, found in required_commands.items() if not found]
    if missing_commands:
        warnings.append("Required commands missing: " + ", ".join(missing_commands))
    if not is_root:
        warnings.append("Run as root for the most complete host audit")
    for label, result in optional_checks.items():
        if not result["available"]:
            warnings.append(f"Optional check unavailable: {label}")

    return {
        "checked_at": datetime.datetime.now(datetime.timezone.utc)
        .isoformat()
        .replace("+00:00", "Z"),
        "host": hostname,
        "distribution": {
            "id": os_fields.get("ID") or None,
            "id_like": os_fields.get("ID_LIKE", "").split(),
            "pretty_name": os_fields.get("PRETTY_NAME") or None,
        },
        "python": {
            "version": ".".join(str(part) for part in python_version[:3]),
            "supported": python_supported,
        },
        "required_commands": required_commands,
        "package_manager_commands": package_manager_commands,
        "optional_checks": optional_checks,
        "privileges": {"root": bool(is_root)},
        "ready": python_supported and not missing_commands,
        "warnings": warnings,
    }


def _print_text(result):
    status = "READY" if result["ready"] else "NEEDS ATTENTION"
    print(f"SecureWatch preflight: {status}")
    distribution = result["distribution"]
    display_name = distribution["pretty_name"] or distribution["id"] or "unknown"
    print(f"Distribution: {display_name}")
    print(
        f"Python {result['python']['version']}: "
        f"{'supported' if result['python']['supported'] else 'unsupported'}"
    )
    missing = [
        command
        for command, available in result["required_commands"].items()
        if not available
    ]
    print(
        "Required commands: "
        + ("all available" if not missing else "missing " + ", ".join(missing))
    )
    manager_commands = result["package_manager_commands"]
    print(
        "Package manager commands found: "
        + (", ".join(manager_commands) if manager_commands else "none")
    )
    available_checks = [
        label
        for label, check in result["optional_checks"].items()
        if check["available"]
    ]
    print(
        "Optional checks available: "
        + (", ".join(available_checks) if available_checks else "none detected")
    )
    if result["warnings"]:
        print("Notes:")
        for warning in result["warnings"]:
            print(f"- {warning}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--json", action="store_true", help="print machine-readable JSON"
    )
    args = parser.parse_args(argv)
    result = inspect_system()
    if args.json:
        print(json.dumps(result, ensure_ascii=True, separators=(",", ":")))
    else:
        _print_text(result)
    return 0 if result["ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
