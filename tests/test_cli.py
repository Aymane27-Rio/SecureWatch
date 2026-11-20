import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from importlib.machinery import SourceFileLoader
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
CLI_PATH = ROOT / "bin" / "securewatch"
SPEC = importlib.util.spec_from_file_location("securewatch_cli", CLI_PATH)
if SPEC is None or SPEC.loader is None:
    SPEC = importlib.util.spec_from_loader(
        "securewatch_cli", SourceFileLoader("securewatch_cli", str(CLI_PATH))
    )
securewatch_cli = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(securewatch_cli)


class SecureWatchCliTests(unittest.TestCase):
    def test_help_and_version_are_available_without_scanning(self):
        help_result = subprocess.run(
            [sys.executable, str(CLI_PATH), "--help"],
            capture_output=True,
            check=False,
            text=True,
        )
        version_result = subprocess.run(
            [sys.executable, str(CLI_PATH), "--version"],
            capture_output=True,
            check=False,
            text=True,
        )

        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        self.assertIn("scan", help_result.stdout)
        self.assertIn("report", help_result.stdout)
        self.assertIn("integrity", help_result.stdout)
        self.assertIn("doctor", help_result.stdout)
        self.assertEqual(version_result.returncode, 0, version_result.stderr)
        self.assertEqual(version_result.stdout.strip(), "securewatch 0.3.0")

    def test_scan_dispatches_to_the_existing_orchestrator(self):
        with patch.object(
            securewatch_cli.subprocess,
            "run",
            return_value=SimpleNamespace(returncode=23),
        ) as run:
            result = securewatch_cli.main(["scan"])

        self.assertEqual(result, 23)
        self.assertEqual(
            run.call_args.args[0], ["bash", str(ROOT / "scripts/securewatch.sh")]
        )
        self.assertEqual(run.call_args.kwargs["cwd"], ROOT)

    def test_doctor_is_available_to_non_root_users_of_the_installed_cli(self):
        with patch.object(securewatch_cli, "application_root", return_value=ROOT):
            with patch.object(securewatch_cli, "INSTALLED_ROOT", ROOT):
                with patch.object(securewatch_cli.os, "geteuid", return_value=1000):
                    with patch.object(
                        securewatch_cli.subprocess,
                        "run",
                        return_value=SimpleNamespace(returncode=0),
                    ) as run:
                        result = securewatch_cli.main(["doctor", "--json"])

        self.assertEqual(result, 0)
        self.assertEqual(
            run.call_args.args[0],
            [sys.executable, str(ROOT / "python/doctor.py"), "--json"],
        )
        self.assertEqual(run.call_args.kwargs["cwd"], ROOT)

    def test_report_uses_latest_configured_scan_and_private_output(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            log_dir = root / "logs"
            report_dir = root / "reports"
            log_dir.mkdir()
            report_dir.mkdir()
            events_path = log_dir / "events_latest.json"
            events_path.write_text(
                json.dumps(
                    [
                        {
                            "ts": "2026-01-01T00:00:00Z",
                            "host": "test-host",
                            "category": "audit",
                            "severity": 2,
                            "summary": "<unsafe>",
                            "data": {},
                        }
                    ]
                ),
                encoding="utf-8",
            )
            config_path = root / "securewatch.conf"
            config_path.write_text(
                f'BASE_DIR="{root}"\n'
                f'LOG_DIR="{log_dir}"\n'
                f'REPORT_DIR="{report_dir}"\n'
                f'STATE_DIR="{root / "state"}"\n',
                encoding="utf-8",
            )
            result = subprocess.run(
                [sys.executable, str(CLI_PATH), "report"],
                capture_output=True,
                check=False,
                text=True,
                env={**os.environ, "SECUREWATCH_CONFIG": str(config_path)},
            )
            output_path = report_dir / "report_events_latest.html"

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(output_path.is_file())
            self.assertIn("&lt;unsafe&gt;", output_path.read_text(encoding="utf-8"))
            self.assertEqual(output_path.stat().st_mode & 0o777, 0o600)

    def test_integrity_cli_initializes_and_verifies_a_configured_baseline(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            state_dir = root / "state"
            target = root / "critical.conf"
            target.write_text("setting=initial\n", encoding="utf-8")
            config_path = root / "securewatch.conf"
            config_path.write_text(
                f'BASE_DIR="{root}"\n'
                f'LOG_DIR="{root / "logs"}"\n'
                f'REPORT_DIR="{root / "reports"}"\n'
                f'STATE_DIR="{state_dir}"\n'
                f'INTEGRITY_BASELINE="{state_dir / "integrity-baseline.json"}"\n',
                encoding="utf-8",
            )
            env = {**os.environ, "SECUREWATCH_CONFIG": str(config_path)}

            initialize = subprocess.run(
                [
                    sys.executable,
                    str(CLI_PATH),
                    "integrity",
                    "init",
                    "--path",
                    str(target),
                ],
                capture_output=True,
                check=False,
                text=True,
                env=env,
            )
            clean = subprocess.run(
                [sys.executable, str(CLI_PATH), "integrity", "verify"],
                capture_output=True,
                check=False,
                text=True,
                env=env,
            )
            target.write_text("setting=changed\n", encoding="utf-8")
            changed = subprocess.run(
                [sys.executable, str(CLI_PATH), "integrity", "verify"],
                capture_output=True,
                check=False,
                text=True,
                env=env,
            )
            strict = subprocess.run(
                [
                    sys.executable,
                    str(CLI_PATH),
                    "integrity",
                    "verify",
                    "--strict",
                ],
                capture_output=True,
                check=False,
                text=True,
                env=env,
            )

        self.assertEqual(initialize.returncode, 0, initialize.stderr)
        self.assertIn("Initialized integrity baseline for 1 files", initialize.stdout)
        self.assertEqual(clean.returncode, 0, clean.stderr)
        self.assertEqual(json.loads(clean.stdout)["severity"], 0)
        self.assertEqual(changed.returncode, 0, changed.stderr)
        change_event = json.loads(changed.stdout)
        self.assertEqual(change_event["severity"], 3)
        self.assertEqual(change_event["data"]["changes"], ["content"])
        self.assertEqual(strict.returncode, 1)
        self.assertEqual(json.loads(strict.stdout)["severity"], 3)


if __name__ == "__main__":
    unittest.main()
