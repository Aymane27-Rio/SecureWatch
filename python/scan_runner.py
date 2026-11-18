#!/usr/bin/env python3
"""Run SecureWatch checks and write a validated JSON event report."""

import argparse
import datetime
import json
import os
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

MODULES = (
    "audit_users.sh",
    "check_ports.sh",
    "firewall_status.sh",
    "check_updates.sh",
    "rkhunter_run.sh",
    "aide_check.sh",
    "file_integrity.sh",
)


def _failure_event(name, reason, exit_code=None, diagnostic=""):
    event = {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "host": socket.gethostname(),
        "category": "audit",
        "severity": 2,
        "summary": f"Audit check failed: {name}",
        "data": {"module": name, "reason": reason},
    }
    if exit_code is not None:
        event["data"]["exit_code"] = exit_code
    diagnostic = " ".join(diagnostic.split())[:300]
    if diagnostic:
        event["data"]["diagnostic"] = diagnostic
    return event


def parse_module_output(name, output, exit_code, stderr=""):
    """Return valid module events plus an explicit event for failed checks."""
    events = []
    malformed_line = None
    for line_number, line in enumerate(output.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            malformed_line = malformed_line or line_number
            continue
        if not isinstance(event, dict):
            malformed_line = malformed_line or line_number
            continue
        events.append(event)

    if exit_code != 0:
        events.append(_failure_event(name, "nonzero_exit", exit_code, stderr or output))
    if malformed_line is not None:
        events.append(
            _failure_event(
                name,
                f"invalid_json_on_line_{malformed_line}",
                exit_code if exit_code != 0 else None,
                stderr,
            )
        )
    return events


def run_check(name, command, root, output_path=None):
    try:
        result = subprocess.run(
            command,
            check=False,
            cwd=root,
            capture_output=True,
            text=True,
            errors="replace",
        )
        exit_code = result.returncode
        stderr = result.stderr
        output = result.stdout
    except OSError as error:
        exit_code = 127
        stderr = str(error)
        output = ""

    if output_path is not None and output_path.is_file():
        try:
            output = output_path.read_text(encoding="utf-8", errors="replace")
        except OSError as error:
            stderr = f"{stderr} {error}".strip()
            exit_code = exit_code or 1

    return parse_module_output(name, output, exit_code, stderr)


def collect_events(root, work_dir, ssh_threshold):
    root = Path(root).resolve()
    work_dir = Path(work_dir).resolve()
    events = []

    for module in MODULES:
        events.extend(
            run_check(
                module,
                ["bash", str(root / "modules" / module)],
                root,
            )
        )

    parser_output = work_dir / "log_anomalies.ndjson"
    parser_output.unlink(missing_ok=True)
    events.extend(
        run_check(
            "log_parser.py",
            [
                sys.executable,
                str(root / "python" / "log_parser.py"),
                "--threshold",
                str(ssh_threshold),
                "--out",
                str(parser_output),
            ],
            root,
            output_path=parser_output,
        )
    )
    return events


def write_report(output_path, events):
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=output_path.parent,
            prefix=f".{output_path.name}.",
            delete=False,
        ) as report:
            temporary_path = Path(report.name)
            json.dump(events, report, ensure_ascii=False, separators=(",", ":"))
            report.write("\n")
            report.flush()
            os.fsync(report.fileno())
            os.fchmod(report.fileno(), 0o600)
        os.replace(temporary_path, output_path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ssh-threshold", type=int, default=5)
    args = parser.parse_args(argv)
    if args.ssh_threshold < 1:
        parser.error("--ssh-threshold must be at least 1")

    try:
        events = collect_events(args.root, args.work_dir, args.ssh_threshold)
        write_report(args.output, events)
    except (OSError, ValueError) as error:
        print(f"securewatch scan: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
