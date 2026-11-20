import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))

from audit_users import audit_passwd  # noqa: E402


class AccountAuditTests(unittest.TestCase):
    def test_normal_root_account_is_clean(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            passwd = Path(temporary_directory) / "passwd"
            passwd.write_text(
                "root:x:0:0:root:/root:/bin/bash\n"
                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
                encoding="utf-8",
            )

            events = audit_passwd(passwd)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["severity"], 0)
        self.assertEqual(events[0]["summary"], "Only the root account uses UID 0")

    def test_flags_additional_uid_zero_accounts_and_escapes_json_safely(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            passwd = Path(temporary_directory) / "passwd"
            passwd.write_text(
                "root:x:0:0:root:/root:/bin/bash\n"
                'admin"name:x:0:1000:admin:/home/admin:/bin/bash\n',
                encoding="utf-8",
            )

            events = audit_passwd(passwd)

        suspicious = [event for event in events if event["severity"] == 3]
        self.assertEqual(len(suspicious), 1)
        self.assertEqual(suspicious[0]["summary"], "Unexpected UID 0 account detected")
        self.assertEqual(suspicious[0]["data"]["user"], 'admin"name')
        self.assertEqual(json.loads(json.dumps(suspicious[0]))["severity"], 3)

    def test_reports_missing_root_and_duplicate_root_entries(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            passwd = Path(temporary_directory) / "passwd"
            passwd.write_text(
                "admin:x:0:1000:admin:/home/admin:/bin/bash\n"
                "root:x:0:0:root:/root:/bin/bash\n"
                "root:x:0:0:duplicate:/root:/bin/bash\n",
                encoding="utf-8",
            )

            events = audit_passwd(passwd)

        summaries = [event["summary"] for event in events]
        self.assertIn("Unexpected UID 0 account detected", summaries)
        self.assertIn("Multiple root entries use UID 0", summaries)

    def test_invalid_entries_are_reported_without_hiding_valid_root(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            passwd = Path(temporary_directory) / "passwd"
            passwd.write_text(
                "root:x:0:0:root:/root:/bin/bash\n"
                "broken:entry\n"
                f"hugeuid:x:{'9' * 30}:1000:invalid:/home/invalid:/bin/bash\n",
                encoding="utf-8",
            )

            events = audit_passwd(passwd)

        self.assertEqual(
            [event["severity"] for event in events],
            [2],
        )
        self.assertEqual(
            events[0]["summary"], "Account database contains invalid entries"
        )
        self.assertEqual(events[0]["data"]["invalid_entries"], 2)

    def test_reports_unreadable_or_missing_passwd_database(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            events = audit_passwd(Path(temporary_directory) / "missing-passwd")

        self.assertEqual(events[0]["severity"], 2)
        self.assertEqual(events[0]["summary"], "Account database could not be read")


if __name__ == "__main__":
    unittest.main()
