import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from webapi.db import get_conn
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


class ShellScriptTests(unittest.TestCase):
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
                (root / "modules" / module_name).write_text(
                    'printf \'{"severity":0,"category":"test"}\\n\'\n',
                    encoding="utf-8",
                )

            (root / "python" / "log_parser.py").write_text(
                "import sys\n"
                "out = sys.argv[sys.argv.index('--out') + 1]\n"
                "open(out, 'w').close()\n",
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
                    "PATH": f"{root / 'bin'}:{env['PATH']}",
                }
            )
            subprocess.run(["bash", str(script)], cwd=root, env=env, check=True)

            event_files = list(logs_dir.glob("events_*.json"))
            report_files = list(reports_dir.glob("report_*.html"))
            self.assertEqual(len(event_files), 1)
            self.assertEqual(len(report_files), 1)
            self.assertEqual(event_files[0].stat().st_mode & 0o777, 0o600)
            self.assertEqual(report_files[0].stat().st_mode & 0o777, 0o600)
            self.assertEqual(logs_dir.stat().st_mode & 0o777, 0o700)
            self.assertEqual(reports_dir.stat().st_mode & 0o777, 0o700)
            self.assertFalse((root / "data").exists())

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


@unittest.skipIf(exporter is None, "prometheus-client is installed in CI")
class ExporterTests(unittest.TestCase):
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
