import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from webapi.db import get_conn
from webapi.ingest import ingest_reports_from_dir

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))

from log_parser import parse_failed_ssh, parse_sudo_anomalies  # noqa: E402
from report_generator import render_html, severity_tag  # noqa: E402


class LogParserTests(unittest.TestCase):
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

        self.assertIn("&lt;script&gt;", report)
        self.assertIn("&lt;img src=x&gt;", report)
        self.assertNotIn("<script>", report)

    def test_known_severity_names(self):
        self.assertEqual(severity_tag(0), "info")
        self.assertEqual(severity_tag(4), "critical")


class ReportIngestionTests(unittest.TestCase):
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


class ShellScriptTests(unittest.TestCase):
    def test_orchestrator_has_valid_bash_syntax(self):
        subprocess.run(
            ["bash", "-n", str(ROOT / "scripts" / "securewatch.sh")], check=True
        )


if __name__ == "__main__":
    unittest.main()
