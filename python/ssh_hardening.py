#!/usr/bin/env python3
"""Audit effective OpenSSH server settings without changing host configuration."""

import argparse
import datetime
import json
import os
import socket
import stat
import subprocess
import time
from pathlib import Path

SSHD_CANDIDATES = (
    "/usr/sbin/sshd",
    "/usr/bin/sshd",
    "/usr/local/sbin/sshd",
    "/sbin/sshd",
    "/run/current-system/sw/bin/sshd",
)
SSHD_TIMEOUT_SECONDS = 10
SSHD_TOTAL_TIMEOUT_SECONDS = 20
SSHD_DISCOVERY_PORT = 22
SSHD_MAX_AUDIT_PORTS = 4
SSHD_CONTEXTS = (
    (
        "root-loopback",
        "user=root,host=localhost,addr=127.0.0.1,laddr=127.0.0.1",
    ),
    (
        "nobody-loopback",
        "user=nobody,host=localhost,addr=127.0.0.1,laddr=127.0.0.1",
    ),
    (
        "root-external-ipv4",
        "user=root,host=audit.invalid,addr=198.51.100.1,laddr=127.0.0.1",
    ),
    (
        "nobody-external-ipv4",
        "user=nobody,host=audit.invalid,addr=198.51.100.1,laddr=127.0.0.1",
    ),
)
REQUIRED_SETTINGS = (
    "permitrootlogin",
    "passwordauthentication",
    "permitemptypasswords",
    "pubkeyauthentication",
    "maxauthtries",
)


def _event(severity, summary, data):
    timestamp = (
        datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    )
    return {
        "ts": timestamp,
        "host": socket.gethostname(),
        "category": "ssh",
        "severity": severity,
        "summary": summary,
        "data": data,
    }


def evaluate_sshd_output(output, context=None):
    """Turn `sshd -T` output into recommendation and coverage events."""

    def contextual(data):
        if context is None:
            return data
        return {**data, "context": context}

    settings = {}
    for line in output.splitlines():
        fields = line.split(None, 1)
        if len(fields) == 2 and fields[0].lower() in REQUIRED_SETTINGS:
            settings[fields[0].lower()] = fields[1].strip().lower()

    missing = [setting for setting in REQUIRED_SETTINGS if setting not in settings]
    invalid = []
    findings = []

    permit_root_login = settings.get("permitrootlogin")
    if permit_root_login == "yes":
        findings.append(
            _event(
                3,
                "SSH permits root login",
                contextual(
                    {
                        "setting": "permitrootlogin",
                        "current": permit_root_login,
                        "recommended": "no",
                    }
                ),
            )
        )
    elif permit_root_login in {
        "prohibit-password",
        "without-password",
        "forced-commands-only",
    }:
        findings.append(
            _event(
                1,
                "SSH permits restricted root login",
                contextual(
                    {
                        "setting": "permitrootlogin",
                        "current": permit_root_login,
                        "recommended": "no",
                    }
                ),
            )
        )
    elif permit_root_login not in {None, "no"}:
        invalid.append("permitrootlogin")

    for name, severity, summary in (
        (
            "passwordauthentication",
            2,
            "SSH password authentication is enabled",
        ),
        (
            "permitemptypasswords",
            4,
            "SSH permits empty passwords",
        ),
    ):
        current = settings.get(name)
        if current == "yes":
            findings.append(
                _event(
                    severity,
                    summary,
                    contextual(
                        {"setting": name, "current": current, "recommended": "no"}
                    ),
                )
            )
        elif current not in {None, "no"}:
            invalid.append(name)

    public_key = settings.get("pubkeyauthentication")
    if public_key == "no":
        findings.append(
            _event(
                1,
                "SSH public key authentication is disabled",
                contextual(
                    {
                        "setting": "pubkeyauthentication",
                        "current": public_key,
                        "recommended": "yes",
                    }
                ),
            )
        )
    elif public_key not in {None, "yes"}:
        invalid.append("pubkeyauthentication")

    max_auth_tries = settings.get("maxauthtries")
    if max_auth_tries is not None:
        try:
            max_auth_tries_value = int(max_auth_tries)
        except ValueError:
            invalid.append("maxauthtries")
        else:
            if max_auth_tries_value < 1:
                invalid.append("maxauthtries")
            elif max_auth_tries_value > 4:
                findings.append(
                    _event(
                        1,
                        "SSH allows more than four authentication attempts",
                        contextual(
                            {
                                "setting": "maxauthtries",
                                "current": max_auth_tries_value,
                                "recommended_maximum": 4,
                            }
                        ),
                    )
                )

    if missing or invalid:
        findings.append(
            _event(
                2,
                "SSH hardening settings could not be fully verified",
                contextual(
                    {
                        "missing_settings": missing,
                        "invalid_settings": sorted(set(invalid)),
                    }
                ),
            )
        )
    if not findings:
        return [
            _event(
                0,
                "SSH authentication settings meet the local baseline",
                contextual({"verified_settings": len(REQUIRED_SETTINGS)}),
            )
        ]
    return findings


def _trusted_executable(candidate):
    try:
        executable = Path(candidate).resolve(strict=True)
        executable_info = executable.stat()
    except (OSError, RuntimeError):
        return None

    allowed_owners = {0}
    if os.geteuid() != 0:
        allowed_owners.add(os.geteuid())
    if (
        not stat.S_ISREG(executable_info.st_mode)
        or not executable_info.st_mode & 0o111
        or executable_info.st_uid not in allowed_owners
        or stat.S_IMODE(executable_info.st_mode) & 0o022
    ):
        return None

    for parent in executable.parents:
        try:
            parent_info = parent.stat(follow_symlinks=False)
        except OSError:
            return None
        if (
            not stat.S_ISDIR(parent_info.st_mode)
            or parent_info.st_uid not in allowed_owners
            or (
                stat.S_IMODE(parent_info.st_mode) & 0o022
                and not parent_info.st_mode & stat.S_ISVTX
            )
        ):
            return None
    if not os.access(executable, os.X_OK):
        return None
    return str(executable)


def locate_sshd():
    for candidate in SSHD_CANDIDATES:
        executable = _trusted_executable(candidate)
        if executable:
            return executable
    return None


def _context_names_from(contexts, index):
    return [name for position, (name, _) in enumerate(contexts) if position >= index]


def _parse_configured_ports(output):
    ports = []
    invalid = []
    for line in output.splitlines():
        fields = line.split()
        if not fields or fields[0].lower() != "port":
            continue
        if (
            len(fields) != 2
            or not fields[1].isascii()
            or not fields[1].isdigit()
            or len(fields[1]) > 5
        ):
            invalid.append(" ".join(fields)[:80])
            continue
        port = int(fields[1])
        if not 1 <= port <= 65535:
            invalid.append(" ".join(fields)[:80])
            continue
        if port not in ports:
            ports.append(port)
    return ports, invalid


def _run_sshd_context(executable, context_name, connection, start, unchecked):
    remaining = SSHD_TOTAL_TIMEOUT_SECONDS - (time.monotonic() - start)
    if remaining <= 0:
        return None, _event(
            2,
            "OpenSSH context inspection exceeded its time budget",
            {
                "context": context_name,
                "contexts_not_checked": unchecked,
                "timeout_seconds": SSHD_TOTAL_TIMEOUT_SECONDS,
            },
        )

    timeout = min(SSHD_TIMEOUT_SECONDS, remaining)
    try:
        result = subprocess.run(
            [executable, "-T", "-C", connection],
            check=False,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return None, _event(
            2,
            "OpenSSH context inspection timed out",
            {
                "context": context_name,
                "contexts_not_checked": unchecked,
                "timeout_seconds": timeout,
            },
        )
    except OSError as error:
        return None, _event(
            2,
            "OpenSSH settings inspection failed",
            {
                "context": context_name,
                "reason": str(error)[:200],
                "contexts_not_checked": unchecked,
            },
        )

    if result.returncode != 0:
        reason = " ".join((result.stderr or "").split())[:200]
        return None, _event(
            2,
            "OpenSSH settings inspection failed",
            {
                "context": context_name,
                "exit_code": result.returncode,
                "reason": reason,
                "contexts_not_checked": unchecked,
            },
        )
    return result, None


def inspect_sshd():
    executable = locate_sshd()
    if executable is None:
        return [
            _event(
                1,
                "OpenSSH server is not installed; SSH settings were not audited",
                {},
            )
        ]

    start = time.monotonic()
    first_context_name, first_connection = SSHD_CONTEXTS[0]
    discovery_result, error_event = _run_sshd_context(
        executable,
        "port-discovery",
        f"{first_connection},lport={SSHD_DISCOVERY_PORT}",
        start,
        ["configured SSH port contexts"],
    )
    if error_event:
        error_event["data"]["contexts_checked"] = []
        return [error_event]

    ports, invalid_ports = _parse_configured_ports(discovery_result.stdout)
    findings = []
    if invalid_ports:
        findings.append(
            _event(
                2,
                "Some SSH listener ports could not be verified",
                {"invalid_ports": invalid_ports},
            )
        )
    if not ports:
        findings.append(
            _event(
                2,
                "SSH listener ports could not be determined",
                {"reason": "sshd -T did not report a valid port"},
            )
        )
        return findings
    if len(ports) > SSHD_MAX_AUDIT_PORTS:
        findings.append(
            _event(
                2,
                "SSH listener port audit limit reached",
                {
                    "configured_ports": ports,
                    "checked_ports": ports[:SSHD_MAX_AUDIT_PORTS],
                    "maximum_checked_ports": SSHD_MAX_AUDIT_PORTS,
                },
            )
        )
        ports = ports[:SSHD_MAX_AUDIT_PORTS]

    audit_contexts = [
        (
            f"{context_name}-port-{port}",
            f"{connection},lport={port}",
        )
        for port in ports
        for context_name, connection in SSHD_CONTEXTS
    ]
    checked_contexts = []
    clean_contexts = []
    for index, (context_name, connection) in enumerate(audit_contexts):
        if (
            context_name == f"{first_context_name}-port-{SSHD_DISCOVERY_PORT}"
            and discovery_result is not None
            and SSHD_DISCOVERY_PORT in ports
        ):
            result = discovery_result
        else:
            result, error_event = _run_sshd_context(
                executable,
                context_name,
                connection,
                start,
                _context_names_from(audit_contexts, index + 1),
            )
            if error_event:
                error_event["data"]["contexts_checked"] = checked_contexts
                findings.append(error_event)
                break

        checked_contexts.append(context_name)
        context_events = evaluate_sshd_output(result.stdout, context=context_name)
        if len(context_events) == 1 and context_events[0]["severity"] == 0:
            clean_contexts.append(context_name)
        else:
            findings.extend(context_events)

    if not findings:
        return [
            _event(
                0,
                "SSH authentication settings meet the baseline in sampled contexts",
                {
                    "verified_settings": len(REQUIRED_SETTINGS),
                    "contexts": clean_contexts,
                },
            )
        ]
    return findings


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)
    for event in inspect_sshd():
        print(json.dumps(event, ensure_ascii=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
