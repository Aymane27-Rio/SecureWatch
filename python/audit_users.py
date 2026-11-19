#!/usr/bin/env python3
"""Check the local passwd database for unexpected accounts with UID 0."""

import argparse
import datetime
import json
import socket
from pathlib import Path

MAX_PASSWD_BYTES = 4 * 1024 * 1024
MAX_PASSWD_LINES = 100_000


def _event(severity, summary, data):
    timestamp = (
        datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    )
    return {
        "ts": timestamp,
        "host": socket.gethostname(),
        "category": "accounts",
        "severity": severity,
        "summary": summary,
        "data": data,
    }


def audit_passwd(passwd_path):
    """Return account audit events without modifying the passwd database."""
    passwd_path = Path(passwd_path)
    try:
        with passwd_path.open("rb") as source:
            content = source.read(MAX_PASSWD_BYTES + 1)
    except OSError as error:
        return [
            _event(
                2,
                "Account database could not be read",
                {"reason": str(error)[:200]},
            )
        ]

    if len(content) > MAX_PASSWD_BYTES:
        return [
            _event(
                2,
                "Account database exceeds the size limit",
                {"limit_bytes": MAX_PASSWD_BYTES},
            )
        ]

    lines = content.decode("utf-8", errors="surrogateescape").splitlines()
    if len(lines) > MAX_PASSWD_LINES:
        return [
            _event(
                2,
                "Account database exceeds the entry limit",
                {"limit_entries": MAX_PASSWD_LINES},
            )
        ]

    uid_zero_accounts = []
    invalid_entries = 0
    for line_number, line in enumerate(lines, start=1):
        if not line or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) != 7 or "\0" in line:
            invalid_entries += 1
            continue
        username, _password, uid_text, gid_text, _gecos, _home, shell = fields
        if (
            not username
            or not uid_text.isascii()
            or not uid_text.isdigit()
            or not gid_text.isascii()
            or not gid_text.isdigit()
            or len(uid_text) > 20
            or len(gid_text) > 20
        ):
            invalid_entries += 1
            continue
        try:
            uid = int(uid_text)
            int(gid_text)
        except ValueError:
            invalid_entries += 1
            continue
        if uid == 0:
            uid_zero_accounts.append(
                {"user": username, "shell": shell, "line": line_number}
            )

    events = []
    root_accounts = [
        account for account in uid_zero_accounts if account["user"] == "root"
    ]
    for account in uid_zero_accounts:
        if account["user"] != "root":
            events.append(
                _event(
                    3,
                    "Unexpected UID 0 account detected",
                    account,
                )
            )

    if not root_accounts:
        events.append(
            _event(
                3,
                "No root account uses UID 0",
                {"uid_zero_accounts": len(uid_zero_accounts)},
            )
        )
    elif len(root_accounts) > 1:
        events.append(
            _event(
                3,
                "Multiple root entries use UID 0",
                {"entries": len(root_accounts)},
            )
        )

    if invalid_entries:
        events.append(
            _event(
                2,
                "Account database contains invalid entries",
                {"invalid_entries": invalid_entries},
            )
        )

    if not events:
        events.append(
            _event(
                0,
                "Only the root account uses UID 0",
                {"uid_zero_accounts": len(uid_zero_accounts)},
            )
        )
    return events


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--passwd-file",
        type=Path,
        default=Path("/etc/passwd"),
        help=argparse.SUPPRESS,
    )
    args = parser.parse_args(argv)
    for event in audit_passwd(args.passwd_file):
        print(json.dumps(event, ensure_ascii=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
