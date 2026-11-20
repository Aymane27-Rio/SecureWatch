#!/usr/bin/env python3
"""Create and verify a private SHA-256 baseline for critical local files."""

import argparse
import datetime
import errno
import hashlib
import json
import os
import re
import socket
import stat
import sys
import tempfile
from pathlib import Path

SCHEMA_VERSION = 1
MAX_BASELINE_BYTES = 2 * 1024 * 1024
MAX_TRACKED_FILES = 256
MAX_TRACKED_FILE_BYTES = 10 * 1024 * 1024
MAX_TOTAL_TRACKED_BYTES = 50 * 1024 * 1024
DEFAULT_PATHS = (
    "/etc/passwd",
    "/etc/group",
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class BaselineError(ValueError):
    """Raised when a baseline or a tracked file cannot be trusted."""


class SymlinkPathError(BaselineError):
    """Raised when a tracked path has become a symlink."""


class TrackedPathTypeError(BaselineError):
    """Raised when a tracked path is no longer a regular file."""


def _timestamp():
    return (
        datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    )


def _absolute_path(value):
    try:
        raw_path = os.fsdecode(os.fspath(value))
    except TypeError as error:
        raise BaselineError("path is invalid") from error
    if "\0" in raw_path or len(raw_path) > 4096:
        raise BaselineError("path is invalid")
    path = Path(raw_path).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    return Path(os.path.abspath(path))


def _check_private_parent(path, create=False):
    parent = path.parent
    if create:
        missing = []
        current = parent
        while not current.exists():
            missing.append(current)
            if current.parent == current:
                raise BaselineError("could not find an existing parent directory")
            current = current.parent
        try:
            resolved_existing = current.resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise BaselineError("baseline ancestor directory is unavailable") from error
        if resolved_existing != current:
            raise BaselineError("baseline path must not use symlinked directories")
        if not current.is_dir():
            raise BaselineError("baseline ancestor is not a directory")
        for directory in reversed(missing):
            directory.mkdir(mode=0o700)

    try:
        resolved_parent = parent.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise BaselineError("baseline parent directory is unavailable") from error
    if resolved_parent != parent:
        raise BaselineError("baseline path must not use symlinked directories")

    expected_owner = os.geteuid()
    try:
        parent_info = parent.stat(follow_symlinks=False)
    except OSError as error:
        raise BaselineError("baseline parent directory is unavailable") from error
    if not stat.S_ISDIR(parent_info.st_mode):
        raise BaselineError("baseline parent is not a directory")
    if parent_info.st_uid != expected_owner:
        raise BaselineError("baseline parent must be owned by the current user")
    if stat.S_IMODE(parent_info.st_mode) & 0o077:
        raise BaselineError("baseline parent must have owner-only permissions")

    # A private leaf can still be renamed through an untrusted writable ancestor.
    for ancestor in parent.parents:
        try:
            ancestor_info = ancestor.stat(follow_symlinks=False)
        except OSError as error:
            raise BaselineError("baseline ancestor directory is unavailable") from error
        mode = ancestor_info.st_mode
        if not stat.S_ISDIR(mode):
            raise BaselineError("baseline path contains a non-directory component")
        writable_by_others = bool(stat.S_IMODE(mode) & 0o022)
        sticky_world_writable = bool(mode & stat.S_ISVTX) and bool(
            stat.S_IMODE(mode) & 0o002
        )
        if writable_by_others and not sticky_world_writable:
            raise BaselineError("baseline path has a writable untrusted ancestor")


def _hash_file(path):
    path = Path(os.path.abspath(path))
    try:
        resolved_parent = path.parent.resolve(strict=True)
    except RuntimeError as error:
        raise SymlinkPathError("tracked path uses an invalid directory link") from error
    if resolved_parent != path.parent:
        raise SymlinkPathError("tracked path uses symlinked directories")

    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise BaselineError(
            "this platform cannot safely open files without following symlinks"
        )
    path_info = os.lstat(path)
    if stat.S_ISLNK(path_info.st_mode):
        raise SymlinkPathError("tracked path is a symlink")
    if not stat.S_ISREG(path_info.st_mode):
        raise TrackedPathTypeError("tracked path is not a regular file")

    flags = (
        os.O_RDONLY
        | nofollow
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise TrackedPathTypeError("tracked path is not a regular file")
        if (before.st_dev, before.st_ino) != (path_info.st_dev, path_info.st_ino):
            raise BaselineError("tracked path changed while it was being opened")
        if before.st_size > MAX_TRACKED_FILE_BYTES:
            raise BaselineError("tracked file exceeds the size limit")

        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_TRACKED_FILE_BYTES:
                raise BaselineError("tracked file exceeds the size limit")
            digest.update(chunk)

        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if identity_before != identity_after or total != after.st_size:
            raise BaselineError("tracked file changed while it was being read")

        try:
            resolved_parent_after = path.parent.resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise BaselineError(
                "tracked path changed while it was being read"
            ) from error
        if resolved_parent_after != path.parent:
            raise SymlinkPathError("tracked path uses symlinked directories")
        try:
            path_after = os.lstat(path)
        except OSError as error:
            raise BaselineError(
                "tracked path changed while it was being read"
            ) from error
        if stat.S_ISLNK(path_after.st_mode):
            raise SymlinkPathError("tracked path is a symlink")
        if (path_after.st_dev, path_after.st_ino) != (after.st_dev, after.st_ino):
            raise BaselineError("tracked path changed while it was being read")

        return {
            "sha256": digest.hexdigest(),
            "size": total,
            "mode": stat.S_IMODE(before.st_mode),
            "uid": before.st_uid,
            "gid": before.st_gid,
        }
    finally:
        os.close(descriptor)


def _atomic_write(path, content):
    _check_private_parent(path, create=True)
    if path.is_symlink():
        raise BaselineError("refusing to replace a symlinked baseline")

    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            delete=False,
        ) as output:
            temporary_path = Path(output.name)
            os.fchmod(output.fileno(), 0o600)
            json.dump(content, output, sort_keys=True, separators=(",", ":"))
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_path, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def initialize_baseline(baseline_path, paths=None, force=False):
    """Hash the selected files and atomically store a private baseline."""
    baseline_path = _absolute_path(baseline_path)
    if (baseline_path.exists() or baseline_path.is_symlink()) and not force:
        raise BaselineError("baseline already exists; use --force to replace it")

    use_defaults = paths is None
    selected_paths = DEFAULT_PATHS if use_defaults else paths
    records = []
    missing_paths = []
    seen = set()
    total_size = 0
    for value in selected_paths:
        path = _absolute_path(value)
        path_string = str(path)
        if path_string in seen:
            continue
        seen.add(path_string)
        if len(seen) > MAX_TRACKED_FILES:
            raise BaselineError(f"at most {MAX_TRACKED_FILES} files can be tracked")
        try:
            record = _hash_file(path)
        except FileNotFoundError as error:
            if use_defaults:
                missing_paths.append(path_string)
                continue
            raise BaselineError(
                f"requested file does not exist: {path_string}"
            ) from error
        except OSError as error:
            raise BaselineError(
                f"cannot read {path_string}: {error.strerror}"
            ) from error
        except BaselineError as error:
            raise BaselineError(f"cannot track {path_string}: {error}") from error
        total_size += record["size"]
        if total_size > MAX_TOTAL_TRACKED_BYTES:
            raise BaselineError(
                f"tracked files exceed the {MAX_TOTAL_TRACKED_BYTES}-byte total size limit"
            )
        records.append({"path": path_string, **record})

    if not records:
        raise BaselineError("no readable files were selected for the baseline")

    baseline = {
        "schema_version": SCHEMA_VERSION,
        "created_at": _timestamp(),
        "host": socket.gethostname(),
        "files": records,
    }
    _atomic_write(baseline_path, baseline)
    return {"tracked_files": len(records), "missing_paths": missing_paths}


def _read_baseline(path):
    _check_private_parent(path)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise BaselineError(
            "this platform cannot safely open the baseline without following symlinks"
        )
    path_info = os.lstat(path)
    if stat.S_ISLNK(path_info.st_mode):
        raise BaselineError("baseline must not be a symlink")
    if not stat.S_ISREG(path_info.st_mode):
        raise BaselineError("baseline is not a regular file")
    flags = (
        os.O_RDONLY
        | nofollow
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise BaselineError("baseline is not a regular file")
        if info.st_uid != os.geteuid():
            raise BaselineError("baseline must be owned by the current user")
        if (info.st_dev, info.st_ino) != (path_info.st_dev, path_info.st_ino):
            raise BaselineError("baseline changed while it was being opened")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise BaselineError("baseline must have owner-only permissions")
        if info.st_size > MAX_BASELINE_BYTES:
            raise BaselineError("baseline exceeds the size limit")
        with os.fdopen(descriptor, "rb") as source:
            descriptor = -1
            content = source.read(MAX_BASELINE_BYTES + 1)
        if len(content) > MAX_BASELINE_BYTES:
            raise BaselineError("baseline exceeds the size limit")
    finally:
        if descriptor >= 0:
            os.close(descriptor)

    try:
        decoded_content = content.decode("utf-8")
        baseline = json.loads(decoded_content)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as error:
        raise BaselineError("baseline is not valid UTF-8 JSON") from error
    _validate_baseline(baseline)
    return baseline


def _validate_baseline(baseline):
    if (
        not isinstance(baseline, dict)
        or baseline.get("schema_version") != SCHEMA_VERSION
    ):
        raise BaselineError("baseline schema version is unsupported")
    if not isinstance(baseline.get("host"), str) or not baseline["host"]:
        raise BaselineError("baseline host identity is missing")
    records = baseline.get("files")
    if not isinstance(records, list) or not records or len(records) > MAX_TRACKED_FILES:
        raise BaselineError("baseline file list is invalid")
    seen = set()
    total_size = 0
    for record in records:
        if not isinstance(record, dict):
            raise BaselineError("baseline file entry is invalid")
        path = record.get("path")
        digest = record.get("sha256")
        if (
            not isinstance(path, str)
            or "\0" in path
            or len(path) > 4096
            or not Path(path).is_absolute()
            or os.path.abspath(path) != path
            or path in seen
        ):
            raise BaselineError("baseline file path is invalid")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise BaselineError("baseline file hash is invalid")
        if (
            type(record.get("size")) is not int
            or not 0 <= record["size"] <= MAX_TRACKED_FILE_BYTES
        ):
            raise BaselineError("baseline file size is invalid")
        total_size += record["size"]
        if total_size > MAX_TOTAL_TRACKED_BYTES:
            raise BaselineError("baseline files exceed the total size limit")
        if type(record.get("mode")) is not int or not 0 <= record["mode"] <= 0o7777:
            raise BaselineError("baseline file mode is invalid")
        if type(record.get("uid")) is not int or record["uid"] < 0:
            raise BaselineError("baseline file owner is invalid")
        if type(record.get("gid")) is not int or record["gid"] < 0:
            raise BaselineError("baseline file group is invalid")
        seen.add(path)


def _event(severity, summary, data):
    return {
        "ts": _timestamp(),
        "host": socket.gethostname(),
        "category": "integrity",
        "severity": severity,
        "summary": summary,
        "data": data,
    }


def verify_baseline(baseline_path):
    """Return integrity events without exposing file contents or hashes."""
    baseline_path = _absolute_path(baseline_path)
    try:
        if not baseline_path.exists() and not baseline_path.is_symlink():
            if baseline_path.parent.exists():
                _check_private_parent(baseline_path)
            return [
                _event(
                    1,
                    "File integrity baseline not initialized",
                    {"baseline": str(baseline_path)},
                )
            ]
        baseline = _read_baseline(baseline_path)
    except FileNotFoundError:
        return [
            _event(
                1,
                "File integrity baseline not initialized",
                {"baseline": str(baseline_path)},
            )
        ]
    except (OSError, BaselineError) as error:
        return [
            _event(
                3,
                "File integrity baseline cannot be trusted",
                {"baseline": str(baseline_path), "reason": str(error)[:200]},
            )
        ]

    if baseline["host"] != socket.gethostname():
        return [
            _event(
                3,
                "File integrity baseline belongs to another host",
                {"baseline_host": baseline["host"]},
            )
        ]

    events = []
    for record in baseline["files"]:
        path = Path(record["path"])
        try:
            current = _hash_file(path)
        except FileNotFoundError:
            events.append(_event(3, "Tracked file is missing", {"path": str(path)}))
            continue
        except SymlinkPathError:
            events.append(
                _event(
                    3, "Tracked path was replaced with a symlink", {"path": str(path)}
                )
            )
            continue
        except TrackedPathTypeError:
            events.append(
                _event(
                    3, "Tracked path is no longer a regular file", {"path": str(path)}
                )
            )
            continue
        except OSError as error:
            if error.errno == errno.ELOOP:
                events.append(
                    _event(
                        3,
                        "Tracked path was replaced with a symlink",
                        {"path": str(path)},
                    )
                )
                continue
            events.append(
                _event(
                    2,
                    "Tracked file could not be verified",
                    {"path": str(path), "reason": str(error)[:200]},
                )
            )
            continue
        except BaselineError as error:
            events.append(
                _event(
                    2,
                    "Tracked file could not be verified",
                    {"path": str(path), "reason": str(error)[:200]},
                )
            )
            continue

        changes = []
        if current["sha256"] != record["sha256"]:
            changes.append("content")
        if current["mode"] != record["mode"]:
            changes.append("mode")
        if current["uid"] != record["uid"] or current["gid"] != record["gid"]:
            changes.append("owner")
        if changes:
            events.append(
                _event(
                    3,
                    "Tracked file changed since baseline",
                    {"path": str(path), "changes": changes},
                )
            )

    if not events:
        events.append(
            _event(
                0,
                "No file integrity changes detected",
                {"tracked_files": len(baseline["files"])},
            )
        )
    return events


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="operation", required=True)
    initialize = subparsers.add_parser("init", help="create a private file baseline")
    initialize.add_argument("--baseline", type=Path, required=True)
    initialize.add_argument("--path", action="append", help="file to track; repeatable")
    initialize.add_argument(
        "--force", action="store_true", help="replace an existing baseline"
    )
    verify = subparsers.add_parser("verify", help="compare tracked files with baseline")
    verify.add_argument("--baseline", type=Path, required=True)
    verify.add_argument(
        "--strict",
        action="store_true",
        help="exit nonzero when verification is incomplete or finds changes",
    )
    args = parser.parse_args(argv)

    try:
        if args.operation == "init":
            result = initialize_baseline(
                args.baseline, paths=args.path, force=args.force
            )
            message = f"Initialized integrity baseline for {result['tracked_files']} files at {args.baseline}"
            if result["missing_paths"]:
                message += (
                    f"; skipped {len(result['missing_paths'])} absent default paths"
                )
            print(message)
            return 0

        events = verify_baseline(args.baseline)
        for event in events:
            print(json.dumps(event, separators=(",", ":")))
        if args.strict and any(event["severity"] > 0 for event in events):
            return 1
        return 0
    except (OSError, BaselineError) as error:
        print(f"securewatch integrity: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
