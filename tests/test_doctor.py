import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))

from doctor import _parse_os_release, inspect_system, main  # noqa: E402


class SecureWatchDoctorTests(unittest.TestCase):
    @staticmethod
    def command_lookup(available):
        return lambda command: f"/usr/bin/{command}" if command in available else None

    def test_reports_distro_prerequisites_and_available_optional_audits(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            os_release = Path(temporary_directory) / "os-release"
            os_release.write_text(
                'ID="ubuntu"\nID_LIKE="debian"\n' 'PRETTY_NAME="Ubuntu Secure Test"\n',
                encoding="utf-8",
            )
            result = inspect_system(
                os_release_path=os_release,
                command_lookup=self.command_lookup(
                    {
                        "bash",
                        "flock",
                        "python3",
                        "apt",
                        "apt-get",
                        "ss",
                        "nft",
                    }
                ),
                ssh_server_lookup=lambda: None,
                python_version=(3, 12, 2),
                is_root=False,
                hostname="doctor-test",
            )

        self.assertTrue(result["ready"])
        self.assertEqual(result["host"], "doctor-test")
        self.assertEqual(result["distribution"]["id"], "ubuntu")
        self.assertEqual(result["distribution"]["id_like"], ["debian"])
        self.assertEqual(result["package_manager_commands"], ["apt", "apt-get"])
        self.assertTrue(result["optional_checks"]["Package update audit"]["available"])
        self.assertTrue(result["optional_checks"]["Listening port audit"]["available"])
        self.assertTrue(result["optional_checks"]["Firewall status audit"]["available"])
        self.assertIn("Run as root", " ".join(result["warnings"]))
        self.assertIn("Optional check unavailable: AIDE", " ".join(result["warnings"]))

    def test_does_not_execute_os_release_content(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            marker = root / "executed"
            os_release = root / "os-release"
            os_release.write_text(
                f"ID=$(touch {marker})\n" f'PRETTY_NAME="$(touch {marker})"\n',
                encoding="utf-8",
            )
            fields, error = _parse_os_release(os_release)

            self.assertIsNone(error)
            self.assertEqual(fields["ID"], "")
            self.assertFalse(marker.exists())

    def test_reports_missing_runtime_requirements_but_not_optional_tools_as_fatal(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            os_release = Path(temporary_directory) / "os-release"
            os_release.write_text('ID="custom"\n', encoding="utf-8")
            result = inspect_system(
                os_release_path=os_release,
                command_lookup=self.command_lookup({"bash", "flock"}),
                ssh_server_lookup=lambda: None,
                python_version=(3, 10, 13),
                is_root=True,
            )

        self.assertFalse(result["ready"])
        self.assertFalse(result["python"]["supported"])
        self.assertFalse(result["required_commands"]["python3"])
        self.assertTrue(
            all(not check["available"] for check in result["optional_checks"].values())
        )
        self.assertIn("Python 3.11 or newer is required", result["warnings"])

    def test_pacman_update_audit_requires_checkupdates(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            os_release = Path(temporary_directory) / "os-release"
            os_release.write_text('ID="arch"\n', encoding="utf-8")
            without_helper = inspect_system(
                os_release_path=os_release,
                command_lookup=self.command_lookup(
                    {"bash", "flock", "python3", "pacman"}
                ),
                ssh_server_lookup=lambda: None,
                python_version=(3, 12, 2),
                is_root=True,
            )
            with_helper = inspect_system(
                os_release_path=os_release,
                command_lookup=self.command_lookup(
                    {"bash", "flock", "python3", "pacman", "checkupdates"}
                ),
                ssh_server_lookup=lambda: None,
                python_version=(3, 12, 2),
                is_root=True,
            )

        self.assertFalse(
            without_helper["optional_checks"]["Package update audit"]["available"]
        )
        self.assertTrue(
            with_helper["optional_checks"]["Package update audit"]["available"]
        )
        self.assertEqual(
            with_helper["optional_checks"]["Package update audit"]["commands"],
            ["pacman", "checkupdates"],
        )

    def test_handles_unreadable_or_oversized_os_release(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            os_release = Path(temporary_directory) / "os-release"
            os_release.write_text("ID=ubuntu\n", encoding="utf-8")
            with patch("doctor.MAX_OS_RELEASE_BYTES", 4):
                fields, error = _parse_os_release(os_release)

        self.assertEqual(fields, {})
        self.assertEqual(error, "os-release exceeds the size limit")

    def test_json_mode_outputs_machine_readable_results(self):
        expected = {
            "ready": True,
            "optional_checks": {},
            "warnings": [],
        }
        output = io.StringIO()
        with patch("doctor.inspect_system", return_value=expected):
            with contextlib.redirect_stdout(output):
                result = main(["--json"])

        self.assertEqual(result, 0)
        self.assertEqual(json.loads(output.getvalue()), expected)

    def test_text_mode_summarizes_readiness_and_warnings(self):
        expected = {
            "ready": True,
            "distribution": {
                "id": "debian",
                "id_like": [],
                "pretty_name": "Debian Test",
            },
            "python": {"version": "3.12.0", "supported": True},
            "required_commands": {"bash": True, "flock": True, "python3": True},
            "package_manager_commands": ["apt-get"],
            "optional_checks": {
                "AIDE database audit": {"available": False, "commands": []}
            },
            "warnings": ["Optional check unavailable: AIDE database audit"],
        }
        output = io.StringIO()
        with patch("doctor.inspect_system", return_value=expected):
            with contextlib.redirect_stdout(output):
                result = main([])

        self.assertEqual(result, 0)
        self.assertIn("SecureWatch preflight: READY", output.getvalue())
        self.assertIn("Distribution: Debian Test", output.getvalue())
        self.assertIn(
            "Optional check unavailable: AIDE database audit", output.getvalue()
        )


if __name__ == "__main__":
    unittest.main()
