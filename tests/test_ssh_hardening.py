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
    SSHD_CONTEXTS,
    SSHD_MAX_AUDIT_PORTS,
    _trusted_executable,
    _parse_configured_ports,
    evaluate_sshd_output,
    inspect_sshd,
    locate_sshd,
)

SAFE_SETTINGS = """\
port 22
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

    def test_includes_context_on_context_specific_findings(self):
        output = SAFE_SETTINGS.replace("permitrootlogin no", "permitrootlogin yes")

        events = evaluate_sshd_output(output, context="root-loopback")

        self.assertEqual(events[0]["data"]["context"], "root-loopback")

    def test_parses_unique_valid_listener_ports_and_reports_invalid_values(self):
        ports, invalid = _parse_configured_ports(
            "port 22\nport 2222\nport 22\nport 0\nport 65536\nport 999999\n"
        )

        self.assertEqual(ports, [22, 2222])
        self.assertEqual(invalid, ["port 0", "port 65536", "port 999999"])

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

    def test_runs_sshd_for_each_representative_effective_configuration(self):
        completed = SimpleNamespace(returncode=0, stdout=SAFE_SETTINGS, stderr="")
        with patch("ssh_hardening.locate_sshd", return_value="/usr/sbin/sshd"):
            with patch("ssh_hardening.subprocess.run", return_value=completed) as run:
                events = inspect_sshd()

        self.assertEqual(run.call_count, len(SSHD_CONTEXTS))
        for call_args, (_, connection) in zip(run.call_args_list, SSHD_CONTEXTS):
            self.assertEqual(
                call_args.args[0],
                ["/usr/sbin/sshd", "-T", "-C", f"{connection},lport=22"],
            )
            self.assertLessEqual(call_args.kwargs["timeout"], 10)
            self.assertEqual(call_args.kwargs["check"], False)
        self.assertEqual(events[0]["severity"], 0)
        self.assertEqual(
            events[0]["data"]["contexts"],
            [f"{name}-port-22" for name, _ in SSHD_CONTEXTS],
        )

    def test_audits_nonstandard_listener_ports(self):
        custom_port_settings = SAFE_SETTINGS.replace("port 22", "port 2222")
        completed = SimpleNamespace(returncode=0, stdout=SAFE_SETTINGS, stderr="")
        with patch("ssh_hardening.locate_sshd", return_value="/usr/sbin/sshd"):
            with patch(
                "ssh_hardening.subprocess.run",
                side_effect=[
                    SimpleNamespace(
                        returncode=0, stdout=custom_port_settings, stderr=""
                    ),
                    completed,
                    completed,
                    completed,
                    completed,
                ],
            ) as run:
                events = inspect_sshd()

        self.assertEqual(run.call_count, len(SSHD_CONTEXTS) + 1)
        self.assertEqual(run.call_args_list[0].args[0][-1].split(",")[-1], "lport=22")
        self.assertTrue(
            all(
                call.args[0][-1].endswith("lport=2222")
                for call in run.call_args_list[1:]
            )
        )
        self.assertEqual(events[0]["severity"], 0)
        self.assertEqual(
            events[0]["data"]["contexts"],
            [f"{name}-port-2222" for name, _ in SSHD_CONTEXTS],
        )

    def test_marks_audit_incomplete_when_configured_port_limit_is_exceeded(self):
        settings = SAFE_SETTINGS + "port 2222\nport 2223\nport 2224\nport 2225\n"
        completed = SimpleNamespace(returncode=0, stdout=SAFE_SETTINGS, stderr="")
        results = [SimpleNamespace(returncode=0, stdout=settings, stderr="")]
        results.extend([completed] * (SSHD_MAX_AUDIT_PORTS * len(SSHD_CONTEXTS)))
        with patch("ssh_hardening.locate_sshd", return_value="/usr/sbin/sshd"):
            with patch("ssh_hardening.subprocess.run", side_effect=results) as run:
                events = inspect_sshd()

        self.assertEqual(run.call_count, SSHD_MAX_AUDIT_PORTS * len(SSHD_CONTEXTS))
        self.assertEqual(events[0]["severity"], 2)
        self.assertEqual(events[0]["summary"], "SSH listener port audit limit reached")
        self.assertEqual(events[0]["data"]["checked_ports"], [22, 2222, 2223, 2224])

    def test_reports_a_match_rule_finding_for_its_nonstandard_port(self):
        custom_port_settings = SAFE_SETTINGS.replace("port 22", "port 2222")
        weak_settings = SAFE_SETTINGS.replace(
            "permitrootlogin no", "permitrootlogin yes"
        )
        completed = SimpleNamespace(returncode=0, stdout=SAFE_SETTINGS, stderr="")
        with patch("ssh_hardening.locate_sshd", return_value="/usr/sbin/sshd"):
            with patch(
                "ssh_hardening.subprocess.run",
                side_effect=[
                    SimpleNamespace(
                        returncode=0, stdout=custom_port_settings, stderr=""
                    ),
                    SimpleNamespace(returncode=0, stdout=weak_settings, stderr=""),
                    completed,
                    completed,
                    completed,
                ],
            ):
                events = inspect_sshd()

        self.assertEqual(events[0]["severity"], 3)
        self.assertEqual(events[0]["data"]["context"], "root-loopback-port-2222")
        self.assertEqual(events[0]["data"]["setting"], "permitrootlogin")

    def test_keeps_findings_if_a_later_context_cannot_be_checked(self):
        weak_settings = SAFE_SETTINGS.replace(
            "permitrootlogin no", "permitrootlogin yes"
        )
        with patch("ssh_hardening.locate_sshd", return_value="/usr/sbin/sshd"):
            with patch(
                "ssh_hardening.subprocess.run",
                side_effect=[
                    SimpleNamespace(returncode=0, stdout=weak_settings, stderr=""),
                    SimpleNamespace(
                        returncode=255, stdout="", stderr="bad configuration"
                    ),
                ],
            ):
                events = inspect_sshd()

        self.assertEqual([event["severity"] for event in events], [3, 2])
        self.assertEqual(events[0]["data"]["context"], "root-loopback-port-22")
        self.assertEqual(events[1]["data"]["context"], "nobody-loopback-port-22")
        self.assertEqual(
            events[1]["data"]["contexts_checked"], ["root-loopback-port-22"]
        )
        self.assertEqual(
            events[1]["data"]["contexts_not_checked"],
            [
                "root-external-ipv4-port-22",
                "nobody-external-ipv4-port-22",
            ],
        )

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
        self.assertEqual(timeout_event["data"]["context"], "port-discovery")
        self.assertEqual(timeout_event["data"]["contexts_checked"], [])
        self.assertEqual(failure_event["severity"], 2)
        self.assertEqual(failure_event["data"]["reason"], "bad configuration line 2")

    def test_stops_before_running_past_the_total_time_budget(self):
        with patch("ssh_hardening.locate_sshd", return_value="/usr/sbin/sshd"):
            with patch("ssh_hardening.time.monotonic", side_effect=[0, 21]):
                with patch("ssh_hardening.subprocess.run") as run:
                    event = inspect_sshd()[0]

        run.assert_not_called()
        self.assertEqual(event["severity"], 2)
        self.assertEqual(event["data"]["contexts_checked"], [])
        self.assertEqual(
            event["data"]["contexts_not_checked"], ["configured SSH port contexts"]
        )


if __name__ == "__main__":
    unittest.main()
