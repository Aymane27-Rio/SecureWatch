import sys
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))

from ssh_hardening import (  # noqa: E402
    _trusted_executable,
    evaluate_sshd_output,
    inspect_sshd,
    locate_sshd,
)

SAFE_SETTINGS = """\
permitrootlogin no
passwordauthentication no
permitemptypasswords no
pubkeyauthentication yes
maxauthtries 4
"""


class SSHHardeningAuditTests(unittest.TestCase):
    def test_accepts_recommended_effective_settings(self):
        events = evaluate_sshd_output(SAFE_SETTINGS)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["severity"], 0)
        self.assertEqual(events[0]["data"]["verified_settings"], 5)

    def test_reports_weak_authentication_settings_by_severity(self):
        output = """\
permitrootlogin yes
passwordauthentication yes
permitemptypasswords yes
pubkeyauthentication no
maxauthtries 8
"""

        events = evaluate_sshd_output(output)

        self.assertEqual([event["severity"] for event in events], [3, 2, 4, 1, 1])
        self.assertEqual(
            [event["data"]["setting"] for event in events],
            [
                "permitrootlogin",
                "passwordauthentication",
                "permitemptypasswords",
                "pubkeyauthentication",
                "maxauthtries",
            ],
        )

    def test_treats_restricted_root_login_as_a_recommendation(self):
        output = SAFE_SETTINGS.replace(
            "permitrootlogin no", "permitrootlogin prohibit-password"
        )

        events = evaluate_sshd_output(output)

        self.assertEqual(events[0]["severity"], 1)
        self.assertEqual(events[0]["data"]["recommended"], "no")

    def test_reports_missing_and_invalid_effective_settings(self):
        events = evaluate_sshd_output("permitrootlogin unknown\nmaxauthtries many\n")

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["severity"], 2)
        self.assertEqual(
            events[0]["data"]["missing_settings"],
            [
                "passwordauthentication",
                "permitemptypasswords",
                "pubkeyauthentication",
            ],
        )
        self.assertEqual(
            events[0]["data"]["invalid_settings"],
            ["maxauthtries", "permitrootlogin"],
        )

    def test_reports_optional_server_as_unavailable(self):
        with patch("ssh_hardening.locate_sshd", return_value=None):
            events = inspect_sshd()

        self.assertEqual(events[0]["severity"], 1)
        self.assertIn("not installed", events[0]["summary"])

    def test_finds_only_trusted_executable_paths(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            executable = Path(temporary_directory) / "sshd"
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(0o700)

            with patch("ssh_hardening.SSHD_CANDIDATES", (str(executable),)):
                self.assertEqual(locate_sshd(), str(executable.resolve()))

            executable.chmod(0o777)
            with patch("ssh_hardening.SSHD_CANDIDATES", (str(executable),)):
                self.assertIsNone(_trusted_executable(executable))

    def test_runs_sshd_in_read_only_effective_configuration_mode(self):
        completed = SimpleNamespace(returncode=0, stdout=SAFE_SETTINGS, stderr="")
        with patch("ssh_hardening.locate_sshd", return_value="/usr/sbin/sshd"):
            with patch("ssh_hardening.subprocess.run", return_value=completed) as run:
                events = inspect_sshd()

        run.assert_called_once_with(
            ["/usr/sbin/sshd", "-T"],
            check=False,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=10,
        )
        self.assertEqual(events[0]["severity"], 0)

    def test_reports_timeout_and_command_failures(self):
        with patch("ssh_hardening.locate_sshd", return_value="/usr/sbin/sshd"):
            with patch(
                "ssh_hardening.subprocess.run",
                side_effect=subprocess.TimeoutExpired(["/usr/sbin/sshd", "-T"], 10),
            ):
                timeout_event = inspect_sshd()[0]
            with patch(
                "ssh_hardening.subprocess.run",
                return_value=SimpleNamespace(
                    returncode=255,
                    stdout="",
                    stderr="bad configuration\nline 2",
                ),
            ):
                failure_event = inspect_sshd()[0]

        self.assertEqual(timeout_event["severity"], 2)
        self.assertEqual(failure_event["severity"], 2)
        self.assertEqual(failure_event["data"]["reason"], "bad configuration line 2")


if __name__ == "__main__":
    unittest.main()
