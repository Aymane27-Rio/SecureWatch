import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCAN_RUNNER_PATH = ROOT / "python" / "scan_runner.py"
SPEC = importlib.util.spec_from_file_location(
    "securewatch_scan_runner", SCAN_RUNNER_PATH
)
scan_runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scan_runner)


class SecureWatchScanRunnerTests(unittest.TestCase):
    def test_nonzero_module_exit_is_reported_without_discarding_findings(self):
        finding = {"category": "test", "severity": 1}
        events = scan_runner.parse_module_output(
            "check_ports.sh",
            json.dumps(finding),
            7,
            "permission denied\nadditional details",
        )

        self.assertEqual(events[0], finding)
        self.assertEqual(events[1]["category"], "audit")
        self.assertEqual(events[1]["severity"], 2)
        self.assertEqual(events[1]["data"]["module"], "check_ports.sh")
        self.assertEqual(events[1]["data"]["reason"], "nonzero_exit")
        self.assertEqual(events[1]["data"]["exit_code"], 7)
        self.assertEqual(
            events[1]["data"]["diagnostic"], "permission denied additional details"
        )

    def test_invalid_module_output_is_reported_and_valid_lines_are_kept(self):
        first_finding = {"category": "test", "severity": 1}
        last_finding = {"category": "test", "severity": 0}
        output = "\n".join(
            [json.dumps(first_finding), "not-json", json.dumps(last_finding)]
        )

        events = scan_runner.parse_module_output("firewall_status.sh", output, 0)

        self.assertEqual(events[0], first_finding)
        self.assertEqual(events[1], last_finding)
        self.assertEqual(events[2]["data"]["reason"], "invalid_json_on_line_2")

    def test_report_is_atomic_valid_json_with_private_permissions(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "logs" / "events.json"
            events = [{"category": "test", "severity": 0}]

            scan_runner.write_report(output, events)

            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), events)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
