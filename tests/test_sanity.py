import fcntl
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from webapi.db import get_conn
from webapi import ingest
from webapi.ingest import ingest_reports_from_dir

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))

import log_parser  # noqa: E402
from log_parser import parse_failed_ssh, parse_sudo_anomalies  # noqa: E402
from report_generator import render_html, severity_tag  # noqa: E402

try:
    from exporters import securewatch_exporter as exporter  # noqa: E402
except ModuleNotFoundError as error:
    if error.name != "prometheus_client":
        raise
    exporter = None


class LogParserTests(unittest.TestCase):
    def test_cli_writes_private_anomaly_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            auth_log = Path(temp_dir) / "auth.log"
            auth_log.write_text(
                "Failed password for root from 192.0.2.8 port 22 ssh2\n",
                encoding="utf-8",
            )
            output = Path(temp_dir) / "anomalies.ndjson"
            with patch.object(log_parser, "AUTH_LOGS", [str(auth_log)]):
                with patch.object(
                    sys,
                    "argv",
                    ["log_parser.py", "--threshold", "1", "--out", str(output)],
                ):
                    log_parser.main()
            mode = output.stat().st_mode & 0o777

        self.assertEqual(mode, 0o600)

    def test_failed_ssh_events_respect_threshold(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "auth.log"
            log_path.write_text(
                "Failed password for root from 192.0.2.8 port 22 ssh2\n"
                "Failed password for invalid user admin from 192.0.2.8 port 22 ssh2\n"
                "Failed password for root from 192.0.2.9 port 22 ssh2\n",
                encoding="utf-8",
            )

            events = parse_failed_ssh(str(log_path), threshold=2)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["data"], {"ip": "192.0.2.8", "count": 2})

    def test_sudo_failures_are_reported(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "auth.log"
            log_path.write_text(
                "sudo: user : authentication failure\n"
                "sudo: user : authentication failure\n",
                encoding="utf-8",
            )

            events = parse_sudo_anomalies(str(log_path))

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["severity"], 1)
        self.assertEqual(events[0]["data"], {"count": 2})


class ReportGeneratorTests(unittest.TestCase):
    def test_html_report_escapes_untrusted_event_content(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "report.html"
            render_html(
                [
                    {
                        "ts": "2026-01-01T00:00:00Z",
                        "host": "host",
                        "category": "auth",
                        "severity": 3,
                        "summary": "<script>alert('x')</script>",
                        "data": {"value": "<img src=x>"},
                    }
                ],
                str(output_path),
            )
            report = output_path.read_text(encoding="utf-8")
            report_mode = output_path.stat().st_mode & 0o777

        self.assertIn("&lt;script&gt;", report)
        self.assertIn("&lt;img src=x&gt;", report)
        self.assertNotIn("<script>", report)
        self.assertEqual(report_mode, 0o600)

    def test_known_severity_names(self):
        self.assertEqual(severity_tag(0), "info")
        self.assertEqual(severity_tag(4), "critical")


class ReportIngestionTests(unittest.TestCase):
    def test_created_database_has_owner_only_permissions(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "state" / "securewatch.db"
            conn = get_conn(db_path)
            conn.close()
            mode = db_path.stat().st_mode & 0o777
            parent_mode = db_path.parent.stat().st_mode & 0o777

        self.assertEqual(mode, 0o600)
        self.assertEqual(parent_mode, 0o700)

    def test_reports_and_events_are_ingested_once(self):
        event = {
            "ts": "2026-01-01T00:00:00Z",
            "host": "host",
            "category": "network",
            "severity": 2,
            "summary": "Listening port",
            "data": {"port": 443},
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            logs_dir = root / "logs"
            logs_dir.mkdir()
            (logs_dir / "events_20260101_000000.json").write_text(
                json.dumps([event]), encoding="utf-8"
            )
            db_path = root / "state" / "securewatch.db"

            first_result = ingest_reports_from_dir(logs_dir, db_path)
            second_result = ingest_reports_from_dir(logs_dir, db_path)
            conn = get_conn(db_path)
            try:
                report_count = conn.execute("SELECT COUNT(*) FROM reports").fetchone()[
                    0
                ]
                rows = conn.execute("SELECT severity, data FROM events").fetchall()
            finally:
                conn.close()

        self.assertEqual(first_result, {"reports": 1, "events": 1})
        self.assertEqual(second_result, {"reports": 0, "events": 0})
        self.assertEqual(report_count, 1)
        self.assertEqual(rows[0][0], 2)
        self.assertEqual(json.loads(rows[0][1]), {"port": 443})

    def test_invalid_report_shapes_are_skipped(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            logs_dir = root / "logs"
            logs_dir.mkdir()
            (logs_dir / "events_20260101_000000.json").write_text(
                json.dumps({"unexpected": "object"}), encoding="utf-8"
            )

            result = ingest_reports_from_dir(
                logs_dir, root / "state" / "securewatch.db"
            )

        self.assertEqual(result, {"reports": 0, "events": 0})

    def test_invalid_event_is_skipped_without_stopping_later_reports(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            logs_dir = root / "logs"
            logs_dir.mkdir()
            (logs_dir / "events_20260101_000000.json").write_text(
                '[{"severity":"invalid"}]', encoding="utf-8"
            )
            (logs_dir / "events_20260101_000001.json").write_text(
                '[{"severity":2,"summary":"valid report"}]', encoding="utf-8"
            )
            db_path = root / "state" / "securewatch.db"

            result = ingest_reports_from_dir(logs_dir, db_path)
            conn = get_conn(db_path)
            try:
                report_ids = [
                    row[0]
                    for row in conn.execute(
                        "SELECT report_id FROM reports ORDER BY report_id"
                    )
                ]
                stored_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[
                    0
                ]
            finally:
                conn.close()

        self.assertEqual(result, {"reports": 1, "events": 1})
        self.assertEqual(report_ids, ["20260101_000001"])
        self.assertEqual(stored_events, 1)

    def test_deeply_nested_report_is_skipped_without_stopping_later_reports(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            logs_dir = root / "logs"
            logs_dir.mkdir()
            deeply_nested = "[" * 1100 + "0" + "]" * 1100
            (logs_dir / "events_20260101_000000.json").write_text(
                deeply_nested, encoding="utf-8"
            )
            (logs_dir / "events_20260101_000001.json").write_text(
                '[{"severity":2,"summary":"valid report"}]', encoding="utf-8"
            )

            result = ingest_reports_from_dir(
                logs_dir, root / "state" / "securewatch.db"
            )

        self.assertEqual(result, {"reports": 1, "events": 1})

    def test_concurrent_ingestion_does_not_duplicate_reports(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            logs_dir = root / "logs"
            logs_dir.mkdir()
            (logs_dir / "events_20260101_000000.json").write_text(
                '[{"severity":2,"summary":"single report"}]', encoding="utf-8"
            )
            db_path = root / "state" / "securewatch.db"
            initialized_conn = get_conn(db_path)
            initialized_conn.close()

            with ThreadPoolExecutor(max_workers=2) as executor:
                results = list(
                    executor.map(
                        lambda _: ingest_reports_from_dir(logs_dir, db_path),
                        range(2),
                    )
                )

            conn = get_conn(db_path)
            try:
                report_count = conn.execute("SELECT COUNT(*) FROM reports").fetchone()[
                    0
                ]
                event_count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            finally:
                conn.close()

        self.assertEqual(sum(result["reports"] for result in results), 1)
        self.assertEqual(report_count, 1)
        self.assertEqual(event_count, 1)

    def test_symlinked_reports_are_not_ingested(self):
        event = {
            "ts": "2026-01-01T00:00:00Z",
            "host": "outside-host",
            "category": "private",
            "severity": 4,
            "summary": "outside file content",
            "data": {"path": "/outside"},
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            logs_dir = root / "logs"
            logs_dir.mkdir()
            outside = root / "outside.json"
            outside.write_text(json.dumps([event]), encoding="utf-8")
            (logs_dir / "events_20260101_000000.json").symlink_to(outside)

            result = ingest_reports_from_dir(
                logs_dir, root / "state" / "securewatch.db"
            )

        self.assertEqual(result, {"reports": 0, "events": 0})

    def test_reports_over_configured_size_limit_are_skipped(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            logs_dir = root / "logs"
            logs_dir.mkdir()
            (logs_dir / "events_20260101_000000.json").write_text(
                "[{}]", encoding="utf-8"
            )

            with patch.object(ingest, "MAX_REPORT_BYTES", 2):
                result = ingest_reports_from_dir(
                    logs_dir, root / "state" / "securewatch.db"
                )

        self.assertEqual(result, {"reports": 0, "events": 0})


class HostPortabilityTests(unittest.TestCase):
    @staticmethod
    def add_system_command_links(bin_dir):
        for command in ("awk", "date", "hostname", "python3"):
            target = shutil.which(command)
            if target:
                (bin_dir / command).symlink_to(target)

    @staticmethod
    def write_command(bin_dir, name, content):
        command = bin_dir / name
        command.write_text(content, encoding="utf-8")
        command.chmod(0o755)
        return command

    def test_dependency_installer_selects_supported_distro_families(self):
        cases = (
            ("debian", "", "apt-get", "apt-get update"),
            ("kali", "debian", "apt-get", "apt-get install -y --no-install-recommends"),
            ("fedora", "", "dnf", "dnf install -y"),
            (
                "opensuse-tumbleweed",
                "suse",
                "zypper",
                "zypper --non-interactive install --no-recommends",
            ),
            ("endeavouros", "arch", "pacman", "pacman -S --needed --noconfirm"),
            (
                "custom-linux",
                "ubuntu debian",
                "apt-get",
                "apt-get install -y --no-install-recommends",
            ),
        )
        for distro_id, distro_like, manager, expected in cases:
            with self.subTest(distro=distro_id), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                bin_dir = root / "bin"
                bin_dir.mkdir()
                os_release = root / "os-release"
                os_release.write_text(
                    f'ID="{distro_id}"\nID_LIKE="{distro_like}"\n',
                    encoding="utf-8",
                )
                log_path = root / "packages.log"
                self.write_command(bin_dir, "sudo", '#!/bin/bash\nexec "$@"\n')
                self.write_command(
                    bin_dir,
                    manager,
                    f'#!/bin/bash\nprintf "{manager} %s\\n" "$*" >> "$PACKAGE_LOG"\n',
                )
                env = {
                    "PATH": str(bin_dir),
                    "PACKAGE_LOG": str(log_path),
                    "SECUREWATCH_OS_RELEASE_FILE": str(os_release),
                }

                result = subprocess.run(
                    ["/bin/bash", str(ROOT / "scripts" / "install.sh")],
                    env=env,
                    capture_output=True,
                    check=False,
                    text=True,
                )

                self.assertEqual(result.returncode, 0, result.stderr)
                package_commands = log_path.read_text(encoding="utf-8")
                self.assertIn(expected, package_commands)
                self.assertIn("gawk", package_commands)
                self.assertIn("aide", package_commands)
                self.assertIn("nmap", package_commands)
                self.assertNotIn("ufw", package_commands)
                self.assertNotIn("firewalld", package_commands)
                if manager == "pacman":
                    self.assertIn("pacman-contrib", package_commands)
                    self.assertIn("fakeroot", package_commands)

    def test_dependency_installer_prefers_dnf5_when_available(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            os_release = root / "os-release"
            os_release.write_text('ID="fedora"\n', encoding="utf-8")
            log_path = root / "packages.log"
            self.write_command(bin_dir, "sudo", '#!/bin/bash\nexec "$@"\n')
            for manager in ("dnf", "dnf5"):
                self.write_command(
                    bin_dir,
                    manager,
                    f'#!/bin/bash\nprintf "{manager} %s\\n" "$*" >> "$PACKAGE_LOG"\n',
                )
            result = subprocess.run(
                ["/bin/bash", str(ROOT / "scripts" / "install.sh")],
                env={
                    "PATH": str(bin_dir),
                    "PACKAGE_LOG": str(log_path),
                    "SECUREWATCH_OS_RELEASE_FILE": str(os_release),
                },
                capture_output=True,
                check=False,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            package_commands = log_path.read_text(encoding="utf-8")
            self.assertIn("dnf5 install -y", package_commands)
            self.assertNotIn("dnf install -y", package_commands)

    def test_dependency_installer_continues_when_optional_tools_are_unavailable(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            os_release = root / "os-release"
            os_release.write_text('ID="fedora"\n', encoding="utf-8")
            log_path = root / "packages.log"
            self.write_command(bin_dir, "sudo", '#!/bin/bash\nexec "$@"\n')
            self.write_command(
                bin_dir,
                "dnf",
                "#!/bin/bash\n"
                'printf "dnf %s\\n" "$*" >> "$PACKAGE_LOG"\n'
                'case "$*" in *" aide"|*" rkhunter"|*" nmap"|*" firewalld") exit 1 ;; esac\n'
                "exit 0\n",
            )
            result = subprocess.run(
                ["/bin/bash", str(ROOT / "scripts" / "install.sh")],
                env={
                    "PATH": str(bin_dir),
                    "PACKAGE_LOG": str(log_path),
                    "SECUREWATCH_OS_RELEASE_FILE": str(os_release),
                },
                capture_output=True,
                check=False,
                text=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("optional package aide could not be installed", result.stderr)
            self.assertIn("optional package nmap could not be installed", result.stderr)

    def test_dependency_installer_does_not_execute_os_release_contents(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            os_release = root / "os-release"
            marker = root / "executed"
            os_release.write_text(
                f'ID="unsupported"\n$(touch {marker})\n', encoding="utf-8"
            )
            result = subprocess.run(
                ["/bin/bash", str(ROOT / "scripts" / "install.sh")],
                env={
                    "PATH": "/usr/bin:/bin",
                    "SECUREWATCH_OS_RELEASE_FILE": str(os_release),
                },
                capture_output=True,
                check=False,
                text=True,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(marker.exists())

    def run_update_check(self, manager, output, exit_code, dnf_version="4.21.0"):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            self.add_system_command_links(bin_dir)
            if manager == "dnf5" or (manager == "dnf" and dnf_version.startswith("5.")):
                expected_args = "check-upgrade --json"
            elif manager == "dnf":
                expected_args = "check-update"
            elif manager == "zypper":
                expected_args = "--non-interactive list-updates"
            elif manager == "pacman":
                expected_args = ""
            else:
                expected_args = "list --upgradable"
            command_name = "checkupdates" if manager == "pacman" else manager
            if manager == "pacman":
                self.write_command(bin_dir, "pacman", "#!/bin/bash\nexit 0\n")
            self.write_command(
                bin_dir,
                command_name,
                "#!/bin/bash\n"
                'if [ "$1" = --version ]; then printf \'%s\\n\' "$DNF_VERSION"; exit 0; fi\n'
                'if [ "$*" != "$EXPECTED_ARGS" ]; then echo "unexpected arguments: $*" >&2; exit 99; fi\n'
                "printf '%s\\n' \"$UPDATE_OUTPUT\"\n"
                'exit "$UPDATE_EXIT_CODE"\n',
            )
            env = {
                "PATH": str(bin_dir),
                "UPDATE_OUTPUT": output,
                "UPDATE_EXIT_CODE": str(exit_code),
                "DNF_VERSION": dnf_version,
                "EXPECTED_ARGS": expected_args,
                "LC_ALL": "C",
            }
            result = subprocess.run(
                ["/bin/bash", str(ROOT / "modules" / "check_updates.sh")],
                env=env,
                capture_output=True,
                check=False,
                text=True,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_apt_update_check_keeps_counting_available_updates(self):
        event = self.run_update_check(
            "apt",
            "Listing... Done\nalpha/stable 1.1 amd64 [upgradable]\nbeta/stable 2.1 amd64 [upgradable]",
            0,
        )

        self.assertEqual(event["severity"], 1)
        self.assertEqual(event["data"], {"count": 2, "manager": "apt"})

    def test_dnf_update_check_counts_updates_and_reports_errors(self):
        updates = self.run_update_check(
            "dnf",
            "alpha.x86_64 1.1 updates\nbeta.noarch 2.1 updates",
            100,
        )
        dnf5_json = '{"Available Packages":[{"name":"gamma","arch":"aarch64"}]}'
        dnf5_updates = self.run_update_check("dnf5", dnf5_json, 100)
        dnf5_compat_updates = self.run_update_check(
            "dnf", dnf5_json, 100, dnf_version="5.2.0"
        )
        clean = self.run_update_check("dnf", "", 0)
        failure = self.run_update_check("dnf", "repository unavailable", 1)

        self.assertEqual(updates["severity"], 1)
        self.assertEqual(updates["data"], {"count": 2, "manager": "dnf"})
        self.assertEqual(dnf5_updates["data"], {"count": 1, "manager": "dnf5"})
        self.assertEqual(dnf5_compat_updates["data"], {"count": 1, "manager": "dnf5"})
        self.assertEqual(clean["severity"], 0)
        self.assertEqual(clean["data"], {"count": 0, "manager": "dnf"})
        self.assertEqual(failure["severity"], 2)
        self.assertEqual(failure["data"], {"manager": "dnf", "exit_code": 1})

    def test_zypper_update_check_counts_table_rows_and_reports_errors(self):
        table = (
            "S | Repository | Name | Current Version | Available Version | Arch\n"
            "--+------------+------+-----------------+-------------------+-----\n"
            "v | Main       | alpha| 1.0             | 1.1               | x86_64\n"
            "v | Main       | beta | 2.0             | 2.1               | noarch"
        )
        updates = self.run_update_check("zypper", table, 0)
        clean = self.run_update_check("zypper", "No updates found", 0)
        failure = self.run_update_check("zypper", "repository unavailable", 7)

        self.assertEqual(updates["data"], {"count": 2, "manager": "zypper"})
        self.assertEqual(clean["data"], {"count": 0, "manager": "zypper"})
        self.assertEqual(failure["severity"], 2)

    def test_pacman_update_check_uses_safe_checkupdates_exit_codes(self):
        updates = self.run_update_check(
            "pacman", "alpha 1.0 -> 1.1\nbeta 2.0 -> 2.1", 0
        )
        clean = self.run_update_check("pacman", "", 2)
        failure = self.run_update_check("pacman", "sync failed", 1)

        self.assertEqual(updates["data"], {"count": 2, "manager": "pacman"})
        self.assertEqual(clean["data"], {"count": 0, "manager": "pacman"})
        self.assertEqual(failure["severity"], 2)

    def test_pacman_update_check_reports_when_checkupdates_is_missing(self):
        with tempfile.TemporaryDirectory() as temp:
            bin_dir = Path(temp)
            self.add_system_command_links(bin_dir)
            self.write_command(bin_dir, "pacman", "#!/bin/bash\nexit 0\n")
            result = subprocess.run(
                ["/bin/bash", str(ROOT / "modules" / "check_updates.sh")],
                env={"PATH": str(bin_dir)},
                capture_output=True,
                check=False,
                text=True,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        event = json.loads(result.stdout)
        self.assertEqual(event["severity"], 2)
        self.assertEqual(event["data"], {"manager": "pacman", "exit_code": 127})

    def test_firewalld_status_is_reported_when_ufw_is_absent(self):
        for state, expected_severity, expected_summary in (
            ("running", 0, "firewalld active"),
            ("inactive", 2, "firewalld inactive"),
        ):
            with self.subTest(state=state), tempfile.TemporaryDirectory() as temp:
                bin_dir = Path(temp)
                self.add_system_command_links(bin_dir)
                self.write_command(
                    bin_dir,
                    "firewall-cmd",
                    "#!/bin/bash\n"
                    'if [ "$FIREWALL_STATE" = running ]; then exit 0; fi\n'
                    "exit 1\n",
                )
                result = subprocess.run(
                    ["/bin/bash", str(ROOT / "modules" / "firewall_status.sh")],
                    env={"PATH": str(bin_dir), "FIREWALL_STATE": state},
                    capture_output=True,
                    check=False,
                    text=True,
                )

                self.assertEqual(result.returncode, 0, result.stderr)
                event = json.loads(result.stdout)
                self.assertEqual(event["severity"], expected_severity)
                self.assertEqual(event["summary"], expected_summary)

    def test_nftables_firewall_status_reports_rules_without_claiming_they_are_safe(
        self,
    ):
        cases = (
            (
                "table inet filter { chain input { type filter hook input priority 0; policy drop; } }",
                1,
                "filter-chains-present",
            ),
            ("", 2, "empty"),
        )
        for ruleset, expected_severity, expected_status in cases:
            with self.subTest(
                status=expected_status
            ), tempfile.TemporaryDirectory() as temp:
                bin_dir = Path(temp)
                self.add_system_command_links(bin_dir)
                grep_path = shutil.which("grep")
                if grep_path:
                    (bin_dir / "grep").symlink_to(grep_path)
                self.write_command(
                    bin_dir,
                    "nft",
                    "#!/bin/bash\n"
                    'if [ "$*" != "list ruleset" ]; then exit 99; fi\n'
                    'printf "%s\\n" "$NFT_RULESET"\n'
                    'exit "$NFT_EXIT_CODE"\n',
                )
                result = subprocess.run(
                    ["/bin/bash", str(ROOT / "modules" / "firewall_status.sh")],
                    env={
                        "PATH": str(bin_dir),
                        "NFT_RULESET": ruleset,
                        "NFT_EXIT_CODE": "0",
                    },
                    capture_output=True,
                    check=False,
                    text=True,
                )

                self.assertEqual(result.returncode, 0, result.stderr)
                event = json.loads(result.stdout)
                self.assertEqual(event["severity"], expected_severity)
                self.assertEqual(event["data"]["nftables_status"], expected_status)

    def test_nftables_status_check_errors_are_not_reported_as_a_clean_firewall(self):
        with tempfile.TemporaryDirectory() as temp:
            bin_dir = Path(temp)
            self.add_system_command_links(bin_dir)
            self.write_command(bin_dir, "nft", "#!/bin/bash\nexit 13\n")
            result = subprocess.run(
                ["/bin/bash", str(ROOT / "modules" / "firewall_status.sh")],
                env={"PATH": str(bin_dir)},
                capture_output=True,
                check=False,
                text=True,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        event = json.loads(result.stdout)
        self.assertEqual(event["severity"], 2)
        self.assertEqual(event["data"]["nftables_status"], "error")
        self.assertEqual(event["data"]["exit_code"], 13)


class ShellScriptTests(unittest.TestCase):
    def test_rkhunter_distinguishes_warnings_failures_and_clean_runs(self):
        script = ROOT / "modules" / "rkhunter_run.sh"
        with tempfile.TemporaryDirectory() as temp_dir:
            bin_dir = Path(temp_dir) / "bin"
            bin_dir.mkdir()
            sudo_stub = bin_dir / "sudo"
            sudo_stub.write_text('#!/usr/bin/env bash\nexec "$@"\n', encoding="utf-8")
            sudo_stub.chmod(0o755)
            rkhunter_stub = bin_dir / "rkhunter"
            rkhunter_stub.write_text(
                "#!/usr/bin/env bash\nprintf '%s\\n' \"${RKHUNTER_OUTPUT:-}\"\n"
                'exit "${RKHUNTER_EXIT_CODE:-0}"\n',
                encoding="utf-8",
            )
            rkhunter_stub.chmod(0o755)
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"

            def run_module(output: str, exit_code: str):
                env["RKHUNTER_OUTPUT"] = output
                env["RKHUNTER_EXIT_CODE"] = exit_code
                return subprocess.run(
                    ["bash", str(script)],
                    capture_output=True,
                    check=False,
                    text=True,
                    env=env,
                )

            warnings = run_module("Warning: test finding", "1")
            failure = run_module("database unavailable", "3")
            clean = run_module("", "0")

        self.assertEqual(warnings.returncode, 0)
        self.assertIn('"severity":2', warnings.stdout)
        self.assertIn('"warnings":1', warnings.stdout)
        self.assertEqual(failure.returncode, 0)
        self.assertIn('"summary":"rkhunter check failed"', failure.stdout)
        self.assertIn('"exit_code":3', failure.stdout)
        self.assertNotIn('"severity":0', failure.stdout)
        self.assertEqual(clean.returncode, 0)
        self.assertIn('"severity":0', clean.stdout)
        self.assertIn('"warnings":0', clean.stdout)

    def test_aide_check_uses_private_temp_and_reports_failures(self):
        script = ROOT / "modules" / "aide_check.sh"
        self.assertNotIn("/tmp/aide.out", script.read_text(encoding="utf-8"))

        with tempfile.TemporaryDirectory() as temp_dir:
            bin_dir = Path(temp_dir) / "bin"
            bin_dir.mkdir()
            sudo_stub = bin_dir / "sudo"
            sudo_stub.write_text('#!/usr/bin/env bash\nexec "$@"\n', encoding="utf-8")
            sudo_stub.chmod(0o755)
            aide_stub = bin_dir / "aide"
            aide_stub.write_text(
                "#!/usr/bin/env bash\nprintf '%s\\n' \"${AIDE_OUTPUT:-}\"\n"
                'exit "${AIDE_EXIT_CODE:-0}"\n',
                encoding="utf-8",
            )
            aide_stub.chmod(0o755)

            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            env["AIDE_OUTPUT"] = (
                "AIDE found differences between database and filesystem"
            )
            env["AIDE_EXIT_CODE"] = "1"
            differences = subprocess.run(
                ["bash", str(script)],
                capture_output=True,
                check=False,
                text=True,
                env=env,
            )
            env["AIDE_OUTPUT"] = "permission denied"
            env["AIDE_EXIT_CODE"] = "2"
            failure = subprocess.run(
                ["bash", str(script)],
                capture_output=True,
                check=False,
                text=True,
                env=env,
            )

        self.assertEqual(differences.returncode, 0)
        self.assertIn('"severity":3', differences.stdout)
        self.assertIn("AIDE found differences", differences.stdout)
        self.assertEqual(failure.returncode, 0)
        self.assertIn('"summary":"AIDE check failed"', failure.stdout)
        self.assertIn('"exit_code":2', failure.stdout)
        self.assertNotIn("AIDE no differences", failure.stdout)

    def test_scan_writes_private_artifacts_to_configured_directories(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "project"
            for directory in ("config", "scripts", "modules", "python", "bin"):
                (root / directory).mkdir(parents=True, exist_ok=True)

            script = root / "scripts" / "securewatch.sh"
            script.write_text(
                (ROOT / "scripts" / "securewatch.sh").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            script.chmod(0o755)
            (root / "config" / "securewatch.conf").write_text(
                'BASE_DIR="${BASE_DIR:-$(pwd)}"\n'
                'LOG_DIR="${LOG_DIR:-$BASE_DIR/data/logs}"\n'
                'REPORT_DIR="${REPORT_DIR:-$BASE_DIR/data/reports}"\n'
                'STATE_DIR="${STATE_DIR:-$BASE_DIR/data/state}"\n'
                'SSH_FAILED_THRESHOLD="${SSH_FAILED_THRESHOLD:-5}"\n',
                encoding="utf-8",
            )

            module_names = (
                "audit_users.sh",
                "check_ports.sh",
                "firewall_status.sh",
                "check_updates.sh",
                "rkhunter_run.sh",
                "aide_check.sh",
                "file_integrity.sh",
            )
            for module_name in module_names:
                module_body = 'printf \'{"severity":0,"category":"test"}\\n\'\n'
                if module_name == "check_ports.sh":
                    module_body += "printf 'simulated module failure\\n' >&2\nexit 7\n"
                (root / "modules" / module_name).write_text(
                    module_body,
                    encoding="utf-8",
                )

            (root / "python" / "log_parser.py").write_text(
                "import sys\n"
                "out = sys.argv[sys.argv.index('--out') + 1]\n"
                "open(out, 'w').close()\n",
                encoding="utf-8",
            )
            (root / "python" / "scan_runner.py").write_text(
                (ROOT / "python" / "scan_runner.py").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            (root / "python" / "report_generator.py").write_text(
                "import sys\n"
                "out = sys.argv[sys.argv.index('--out') + 1]\n"
                "with open(out, 'w') as report: report.write('private report')\n",
                encoding="utf-8",
            )
            (root / "bin" / "jq").write_text(
                "#!/usr/bin/env python3\n"
                "import json, sys\n"
                "if sys.argv[1] == '-s':\n"
                "    with open(sys.argv[-1], encoding='utf-8') as events:\n"
                "        json.dump([json.loads(line) for line in events if line.strip()], sys.stdout)\n"
                "else:\n"
                "    print(0)\n",
                encoding="utf-8",
            )
            (root / "bin" / "jq").chmod(0o755)
            curl_args_file = root / "curl-args.log"
            (root / "bin" / "curl").write_text(
                "#!/usr/bin/env bash\n"
                'printf \'%s\\n\' "$@" >> "$CURL_ARGS_FILE"\n'
                "printf '%s\\n' '---request---' >> \"$CURL_ARGS_FILE\"\n"
                "exit 28\n",
                encoding="utf-8",
            )
            (root / "bin" / "curl").chmod(0o755)

            logs_dir = root / "custom" / "logs"
            reports_dir = root / "custom" / "reports"
            state_dir = root / "custom" / "state"
            env = os.environ.copy()
            env.update(
                {
                    "BASE_DIR": str(root),
                    "LOG_DIR": str(logs_dir),
                    "REPORT_DIR": str(reports_dir),
                    "STATE_DIR": str(state_dir),
                    "CURL_ARGS_FILE": str(curl_args_file),
                    "WEBAPI_INGEST_URL": "https://api.example.invalid/ingest",
                    "WEBAPI_API_KEY": "a" * 64,
                    "PATH": f"{root / 'bin'}:{env['PATH']}",
                }
            )

            state_dir.mkdir(parents=True)
            lock_path = state_dir / "scan.lock"
            with lock_path.open("w", encoding="utf-8") as lock_file:
                lock_path.chmod(0o600)
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                rejected_run = subprocess.run(
                    ["bash", str(script)],
                    cwd=root,
                    env=env,
                    capture_output=True,
                    check=False,
                    text=True,
                )
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

            self.assertEqual(rejected_run.returncode, 75)
            self.assertIn("A SecureWatch scan is already running", rejected_run.stderr)
            scan_results = []
            for _ in range(2):
                scan_results.append(
                    subprocess.run(
                        ["bash", str(script)],
                        cwd=root,
                        env=env,
                        capture_output=True,
                        check=True,
                        text=True,
                    )
                )

            event_files = list(logs_dir.glob("events_*.json"))
            report_files = list(reports_dir.glob("report_*.html"))
            self.assertEqual(len(event_files), 2)
            self.assertEqual(len(report_files), 2)
            for scan_result in scan_results:
                self.assertIn("Audit checks failed: 1", scan_result.stdout)
            for event_file in event_files:
                events = json.loads(event_file.read_text(encoding="utf-8"))
                failures = [
                    event
                    for event in events
                    if event.get("summary") == "Audit check failed: check_ports.sh"
                ]
                self.assertEqual(len(failures), 1)
                self.assertEqual(failures[0]["severity"], 2)
                self.assertEqual(failures[0]["data"]["exit_code"], 7)
            self.assertEqual(
                {path.stat().st_mode & 0o777 for path in event_files}, {0o600}
            )
            self.assertEqual(
                {path.stat().st_mode & 0o777 for path in report_files}, {0o600}
            )
            self.assertEqual(logs_dir.stat().st_mode & 0o777, 0o700)
            self.assertEqual(reports_dir.stat().st_mode & 0o777, 0o700)
            self.assertFalse((root / "data").exists())
            curl_calls = [
                call
                for call in curl_args_file.read_text(encoding="utf-8").split(
                    "---request---"
                )
                if call.strip()
            ]
            self.assertEqual(len(curl_calls), 2)
            for call in curl_calls:
                self.assertIn("--connect-timeout\n5", call)
                self.assertIn("--max-time\n15", call)
                self.assertIn("--fail", call)

    def test_slack_webhook_uses_bounded_curl_request(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            curl_args_file = root / "curl-args.log"
            curl = bin_dir / "curl"
            curl.write_text(
                "#!/usr/bin/env bash\n"
                'printf \'%s\\n\' "$@" > "$CURL_ARGS_FILE"\n'
                "exit 28\n",
                encoding="utf-8",
            )
            curl.chmod(0o755)
            jq = bin_dir / "jq"
            jq.write_text(
                "#!/usr/bin/env bash\n" "printf '%s\\n' '{\"text\":\"test\"}'\n",
                encoding="utf-8",
            )
            jq.chmod(0o755)
            mail = bin_dir / "mail"
            mail.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
            mail.chmod(0o755)
            env = os.environ.copy()
            env.update(
                {
                    "CURL_ARGS_FILE": str(curl_args_file),
                    "SLACK_WEBHOOK_URL": "https://hooks.example.invalid/test",
                    "PATH": f"{bin_dir}:{env['PATH']}",
                }
            )

            subprocess.run(
                ["bash", str(ROOT / "scripts" / "notify.sh"), "events.json", "1"],
                env=env,
                check=True,
            )
            curl_args = curl_args_file.read_text(encoding="utf-8")

        self.assertIn("--connect-timeout\n5", curl_args)
        self.assertIn("--max-time\n15", curl_args)
        self.assertIn("--fail", curl_args)

    def test_orchestrator_has_valid_bash_syntax(self):
        subprocess.run(
            ["bash", "-n", str(ROOT / "scripts" / "securewatch.sh")], check=True
        )

    def test_frontend_rejects_unsafe_or_short_api_keys(self):
        script = ROOT / "frontend" / "validate-api-key.sh"
        valid_env = os.environ.copy()
        valid_env["WEBAPI_API_KEY"] = "a" * 64
        subprocess.run(["sh", str(script)], env=valid_env, check=True)

        for api_key in ("short", "a" * 63, "a" * 63 + ";"):
            with self.subTest(api_key=api_key):
                invalid_env = os.environ.copy()
                invalid_env["WEBAPI_API_KEY"] = api_key
                result = subprocess.run(
                    ["sh", str(script)],
                    env=invalid_env,
                    capture_output=True,
                    check=False,
                    text=True,
                )
                self.assertNotEqual(result.returncode, 0)


class FrontendSecurityTests(unittest.TestCase):
    def test_dashboard_can_use_strict_style_policy(self):
        app_source = (ROOT / "frontend" / "src" / "App.jsx").read_text(encoding="utf-8")
        nginx_config = (ROOT / "frontend" / "nginx.conf").read_text(encoding="utf-8")

        self.assertNotIn("style={{", app_source)
        self.assertIn("style-src 'self'", nginx_config)
        self.assertIn("connect-src 'self'", nginx_config)
        self.assertIn('X-Content-Type-Options "nosniff"', nginx_config)
        self.assertIn('X-Frame-Options "DENY"', nginx_config)


class ContainerImagePolicyTests(unittest.TestCase):
    def test_container_images_use_patch_level_version_tags(self):
        image_references = []

        for dockerfile in ROOT.rglob("Dockerfile"):
            for line in dockerfile.read_text(encoding="utf-8").splitlines():
                fields = line.split()
                if fields and fields[0] == "FROM":
                    image_references.append((dockerfile, fields[1]))

        compose_file = ROOT / "docker-compose.yml"
        for line in compose_file.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped.startswith("image:"):
                image_references.append((compose_file, stripped.split(None, 1)[1]))

        self.assertTrue(image_references, "No container image references were found")
        version_tag = re.compile(r"^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
        for source, reference in image_references:
            image = reference.split("@", 1)[0]
            separator = image.rfind(":")
            tag = image.split(":")[-1] if separator > image.rfind("/") else ""
            with self.subTest(source=source.name, image=reference):
                self.assertRegex(tag, version_tag)

    def test_api_images_default_to_non_root_users(self):
        for relative_path in ("webapi/Dockerfile", "backend/Dockerfile"):
            dockerfile = ROOT / relative_path
            with self.subTest(dockerfile=relative_path):
                self.assertIn("USER 1000:1000", dockerfile.read_text(encoding="utf-8"))


class WorkflowSecurityTests(unittest.TestCase):
    def test_ci_covers_kali_arch_and_opensuse_with_digest_pins(self):
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("'feat/**'", workflow)
        self.assertRegex(
            workflow,
            r"(?ms)^  kali-package:\n.*?image: kalilinux/kali-rolling@sha256:[0-9a-f]{64}",
        )
        self.assertRegex(
            workflow,
            r"(?ms)^  opensuse-host-support:\n.*?image: opensuse/tumbleweed@sha256:[0-9a-f]{64}",
        )
        self.assertRegex(
            workflow,
            r"(?ms)^  arch-host-support:\n.*?image: archlinux@sha256:[0-9a-f]{64}",
        )

    def test_github_actions_are_pinned_to_full_commit_shas(self):
        workflow_paths = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
        action_refs = []
        for workflow_path in workflow_paths:
            action_refs.extend(
                re.findall(
                    r"^\s*uses:\s+[^@\s]+@([^\s#]+)(?:\s+#\s*(v[^\s]+))?",
                    workflow_path.read_text(encoding="utf-8"),
                    flags=re.MULTILINE,
                )
            )

        self.assertTrue(action_refs)
        for commit_sha, release_tag in action_refs:
            self.assertRegex(commit_sha, r"^[0-9a-f]{40}$")
            self.assertRegex(release_tag, r"^v\d+\.\d+\.\d+$")


@unittest.skipIf(exporter is None, "prometheus-client is installed in CI")
class ExporterTests(unittest.TestCase):
    def test_exporter_bounds_report_size_and_category_cardinality(self):
        original_log_dir = exporter.LOG_DIR
        with tempfile.TemporaryDirectory() as temp_dir:
            log_dir = Path(temp_dir) / "logs"
            log_dir.mkdir()
            report_path = log_dir / "events_20260101_000000.json"
            report_path.write_text(
                json.dumps(
                    [
                        {"severity": index % 5, "category": f"custom-{index}"}
                        for index in range(100)
                    ]
                ),
                encoding="utf-8",
            )
            exporter.LOG_DIR = str(log_dir)
            try:
                exporter.reset_metrics()
                exporter.tick()
                self.assertEqual(exporter.g_total._value.get(), 100)
                self.assertEqual(exporter.previous_categories, {"other"})
                self.assertEqual(exporter.g_by_cat.labels("other")._value.get(), 100)

                with patch.object(exporter, "MAX_REPORT_BYTES", 1):
                    exporter.tick()
                self.assertEqual(exporter.g_total._value.get(), 0)
            finally:
                exporter.LOG_DIR = original_log_dir
                exporter.reset_metrics()

    def test_bad_and_missing_reports_reset_exported_metrics(self):
        original_log_dir = exporter.LOG_DIR
        with tempfile.TemporaryDirectory() as temp_dir:
            log_dir = Path(temp_dir) / "logs"
            log_dir.mkdir()
            valid_report = log_dir / "events_20260101_000000.json"
            valid_report.write_text(
                '[{"severity":2,"category":"auth"}]', encoding="utf-8"
            )
            outside_report = Path(temp_dir) / "outside.json"
            outside_report.write_text(
                '[{"severity":9,"category":"private"}]', encoding="utf-8"
            )
            (log_dir / "events_20260102_000000.json").symlink_to(outside_report)
            exporter.LOG_DIR = str(log_dir)
            try:
                exporter.tick()
                self.assertEqual(exporter.g_total._value.get(), 1)
                self.assertEqual(exporter.g_by_sev.labels("2")._value.get(), 1)
                self.assertEqual(exporter.previous_severities, {"2"})

                valid_report.write_text("{invalid", encoding="utf-8")
                exporter.tick()
                self.assertEqual(exporter.g_total._value.get(), 0)
                self.assertEqual(exporter.g_by_sev.labels("2")._value.get(), 0)

                valid_report.unlink()
                exporter.tick()
                self.assertEqual(exporter.g_total._value.get(), 0)
            finally:
                exporter.LOG_DIR = original_log_dir


if __name__ == "__main__":
    unittest.main()
