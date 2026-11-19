import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))

from file_integrity import (  # noqa: E402
    BaselineError,
    initialize_baseline,
    verify_baseline,
)


class FileIntegrityBaselineTests(unittest.TestCase):
    def test_initializes_private_baseline_and_reports_clean_files(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            target = root / "ssh_config"
            target.write_text("PermitRootLogin no\n", encoding="utf-8")
            baseline = root / "state" / "integrity-baseline.json"

            result = initialize_baseline(baseline, paths=[target])
            events = verify_baseline(baseline)
            content = json.loads(baseline.read_text(encoding="utf-8"))
            baseline_mode = baseline.stat().st_mode & 0o777
            directory_mode = baseline.parent.stat().st_mode & 0o777

        self.assertEqual(result["tracked_files"], 1)
        self.assertEqual(result["missing_paths"], [])
        self.assertEqual(baseline_mode, 0o600)
        self.assertEqual(directory_mode, 0o700)
        self.assertEqual(content["schema_version"], 1)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["severity"], 0)
        self.assertEqual(events[0]["data"], {"tracked_files": 1})

    def test_reports_content_mode_owner_and_missing_file_changes(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            target = root / "secure.conf"
            target.write_text("value=initial\n", encoding="utf-8")
            baseline = root / "state" / "baseline.json"
            initialize_baseline(baseline, paths=[target])

            target.write_text("value=changed\n", encoding="utf-8")
            content_event = verify_baseline(baseline)[0]
            self.assertEqual(content_event["severity"], 3)
            self.assertIn("content", content_event["data"]["changes"])
            self.assertNotIn("sha256", json.dumps(content_event))
            self.assertNotIn("value=changed", json.dumps(content_event))

            target.chmod(0o600)
            mode_event = verify_baseline(baseline)[0]
            self.assertIn("mode", mode_event["data"]["changes"])

            target.unlink()
            missing_event = verify_baseline(baseline)[0]
            self.assertEqual(missing_event["summary"], "Tracked file is missing")
            self.assertEqual(missing_event["severity"], 3)

    def test_refuses_symlinks_and_unsafe_baseline_permissions(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            target = root / "real.conf"
            target.write_text("safe\n", encoding="utf-8")
            link = root / "link.conf"
            link.symlink_to(target)
            baseline = root / "state" / "baseline.json"

            with self.assertRaises(BaselineError):
                initialize_baseline(baseline, paths=[link])

            initialize_baseline(baseline, paths=[target])
            baseline.chmod(0o644)
            event = verify_baseline(baseline)[0]

        self.assertEqual(event["severity"], 3)
        self.assertEqual(event["summary"], "File integrity baseline cannot be trusted")

    def test_reports_malformed_baseline_without_crashing(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            target = root / "tracked.conf"
            target.write_text("safe\n", encoding="utf-8")
            baseline = root / "state" / "baseline.json"
            initialize_baseline(baseline, paths=[target])
            baseline.write_bytes(b"\xff\xfe")
            baseline.chmod(0o600)

            event = verify_baseline(baseline)[0]

        self.assertEqual(event["severity"], 3)
        self.assertEqual(event["summary"], "File integrity baseline cannot be trusted")

    def test_reports_symlink_replacement_and_file_type_changes(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            target = root / "tracked.conf"
            other = root / "other.conf"
            target.write_text("tracked\n", encoding="utf-8")
            other.write_text("outside\n", encoding="utf-8")
            baseline = root / "state" / "baseline.json"
            initialize_baseline(baseline, paths=[target])

            target.unlink()
            target.symlink_to(other)
            symlink_event = verify_baseline(baseline)[0]
            target.unlink()
            target.mkdir()
            directory_event = verify_baseline(baseline)[0]

        self.assertEqual(symlink_event["severity"], 3)
        self.assertEqual(
            symlink_event["summary"], "Tracked path was replaced with a symlink"
        )
        self.assertEqual(directory_event["severity"], 3)
        self.assertEqual(
            directory_event["summary"], "Tracked path is no longer a regular file"
        )

    def test_detects_path_replacement_during_hashing(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            target = root / "tracked.conf"
            target.write_text("original\n", encoding="utf-8")
            replacement = root / "replacement.conf"
            replacement.write_text("replacement\n", encoding="utf-8")
            baseline = root / "state" / "baseline.json"
            initialize_baseline(baseline, paths=[target])

            real_read = os.read
            replaced = False

            def replace_after_read(descriptor, length):
                nonlocal replaced
                chunk = real_read(descriptor, length)
                if chunk and not replaced:
                    os.replace(replacement, target)
                    replaced = True
                return chunk

            with patch("file_integrity.os.read", side_effect=replace_after_read):
                event = verify_baseline(baseline)[0]

        self.assertTrue(replaced)
        self.assertEqual(event["severity"], 2)
        self.assertIn("changed while it was being read", event["data"]["reason"])

    def test_detects_owner_metadata_changes(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            target = root / "tracked.conf"
            target.write_text("same content\n", encoding="utf-8")
            baseline = root / "state" / "baseline.json"
            initialize_baseline(baseline, paths=[target])
            content = json.loads(baseline.read_text(encoding="utf-8"))
            content["files"][0]["uid"] += 1
            baseline.write_text(json.dumps(content), encoding="utf-8")
            baseline.chmod(0o600)

            event = verify_baseline(baseline)[0]

        self.assertEqual(event["severity"], 3)
        self.assertEqual(event["data"]["changes"], ["owner"])

    def test_rejects_untrusted_parent_directories(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            target = root / "target"
            target.write_text("safe\n", encoding="utf-8")
            parent = root / "state"
            parent.mkdir(mode=0o700)
            baseline = parent / "baseline.json"
            parent.chmod(0o755)

            with self.assertRaises(BaselineError):
                initialize_baseline(baseline, paths=[target])

    def test_refuses_symlinked_baseline_parent_without_creating_through_it(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            real_directory = root / "real"
            real_directory.mkdir()
            linked_directory = root / "linked"
            linked_directory.symlink_to(real_directory, target_is_directory=True)
            target = root / "tracked.conf"
            target.write_text("safe\n", encoding="utf-8")
            baseline = linked_directory / "created" / "baseline.json"

            with self.assertRaises(BaselineError):
                initialize_baseline(baseline, paths=[target])
            self.assertFalse((real_directory / "created").exists())

    def test_rejects_invalid_paths_and_oversized_tracked_files(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            target = root / "tracked.conf"
            target.write_text("four", encoding="utf-8")
            baseline = root / "state" / "baseline.json"

            with self.assertRaisesRegex(BaselineError, "path is invalid"):
                initialize_baseline(root / "bad\0baseline.json", paths=[target])
            with self.assertRaisesRegex(BaselineError, "path is invalid"):
                initialize_baseline(baseline, paths=[root / "bad\0target"])
            with patch("file_integrity.MAX_TRACKED_FILE_BYTES", 3):
                with self.assertRaisesRegex(BaselineError, "size limit"):
                    initialize_baseline(baseline, paths=[target])

    def test_requires_force_to_replace_a_baseline(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            target = root / "target"
            target.write_text("first\n", encoding="utf-8")
            baseline = root / "state" / "baseline.json"
            initialize_baseline(baseline, paths=[target])

            with self.assertRaisesRegex(BaselineError, "use --force"):
                initialize_baseline(baseline, paths=[target])

            target.write_text("second\n", encoding="utf-8")
            initialize_baseline(baseline, paths=[target], force=True)
            events = verify_baseline(baseline)

        self.assertEqual(events[0]["severity"], 0)

    def test_reports_missing_baseline_and_host_mismatch(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            baseline = root / "missing.json"
            missing_event = verify_baseline(baseline)[0]

            target = root / "target"
            target.write_text("safe\n", encoding="utf-8")
            baseline = root / "state" / "baseline.json"
            initialize_baseline(baseline, paths=[target])
            data = json.loads(baseline.read_text(encoding="utf-8"))
            data["host"] = "another-host"
            baseline.write_text(json.dumps(data), encoding="utf-8")
            baseline.chmod(0o600)
            host_event = verify_baseline(baseline)[0]

        self.assertEqual(missing_event["severity"], 1)
        self.assertEqual(
            host_event["summary"],
            "File integrity baseline belongs to another host",
        )
        self.assertEqual(host_event["severity"], 3)

    def test_skips_absent_default_paths_without_claiming_them_tracked(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            target = root / "present.conf"
            target.write_text("present\n", encoding="utf-8")
            baseline = root / "state" / "baseline.json"
            with patch(
                "file_integrity.DEFAULT_PATHS",
                (str(target), str(root / "absent.conf")),
            ):
                result = initialize_baseline(baseline)

        self.assertEqual(result["tracked_files"], 1)
        self.assertEqual(result["missing_paths"], [str(root / "absent.conf")])


if __name__ == "__main__":
    unittest.main()
