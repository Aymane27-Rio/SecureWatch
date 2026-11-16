import datetime
import json
import os
import sqlite3
import stat
from pathlib import Path

from .db import get_conn, init_db

MAX_REPORT_BYTES = int(os.environ.get("WEBAPI_MAX_REPORT_BYTES", 10 * 1024 * 1024))
MAX_REPORT_EVENTS = 100_000
if MAX_REPORT_BYTES < 1:
    raise RuntimeError("WEBAPI_MAX_REPORT_BYTES must be a positive integer")


def _load_report(path):
    if not hasattr(os, "O_NOFOLLOW"):
        raise RuntimeError(
            "Report ingestion requires operating system O_NOFOLLOW support"
        )

    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as report_file:
        metadata = os.fstat(report_file.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("report is not a regular file")
        if metadata.st_size > MAX_REPORT_BYTES:
            raise ValueError("report exceeds WEBAPI_MAX_REPORT_BYTES")

        payload = report_file.read(MAX_REPORT_BYTES + 1)
        if len(payload) > MAX_REPORT_BYTES:
            raise ValueError("report exceeds WEBAPI_MAX_REPORT_BYTES")

    return json.loads(payload.decode("utf-8"))


def _normalize_events(events):
    if not isinstance(events, list):
        raise ValueError("expected a list of event objects")
    if len(events) > MAX_REPORT_EVENTS:
        raise ValueError("expected a list with no more than 100000 events")

    normalized = []
    text_fields = ("ts", "host", "category", "summary")
    for event in events:
        if not isinstance(event, dict):
            raise ValueError("each report event must be an object")
        if any(
            event.get(field) is not None and not isinstance(event.get(field), str)
            for field in text_fields
        ):
            raise ValueError("event text fields must contain strings or null")

        raw_severity = event.get("severity", 0)
        if isinstance(raw_severity, bool):
            raise ValueError("event severity must be an integer from 0 to 4")
        try:
            severity = int(raw_severity)
        except (TypeError, ValueError, OverflowError) as error:
            raise ValueError("event severity must be an integer from 0 to 4") from error
        if isinstance(raw_severity, float) and raw_severity != severity:
            raise ValueError("event severity must be an integer from 0 to 4")
        if not 0 <= severity <= 4:
            raise ValueError("event severity must be an integer from 0 to 4")

        normalized.append(
            (
                event.get("ts"),
                event.get("host"),
                event.get("category"),
                severity,
                event.get("summary"),
                json.dumps(event.get("data", {})),
            )
        )
    return normalized


def ingest_reports_from_dir(logs_dir="/app/data/logs", db_path=None, dry_run=False):
    logs_dir = Path(logs_dir)
    conn = get_conn(db_path)
    init_db(conn)
    cur = conn.cursor()

    inserted_reports = 0
    inserted_events = 0

    try:
        for path in sorted(logs_dir.glob("events_*.json")):
            if path.is_symlink() or not path.is_file():
                continue

            report_id = path.name.removeprefix("events_").removesuffix(".json")
            cur.execute("SELECT 1 FROM reports WHERE report_id=? LIMIT 1", (report_id,))
            if cur.fetchone():
                continue

            try:
                events = _load_report(path)
                normalized_events = _normalize_events(events)
            except (OSError, UnicodeDecodeError, ValueError) as error:
                print(f"Skipping invalid report {path.name}: {error}")
                continue

            total = len(normalized_events)
            now = datetime.datetime.now(datetime.timezone.utc).isoformat()
            if not dry_run:
                try:
                    with conn:
                        cur.execute(
                            "INSERT OR IGNORE INTO reports "
                            "(report_id, filename, ts, total, created_at) "
                            "VALUES (?, ?, ?, ?, ?)",
                            (report_id, path.name, report_id, total, now),
                        )
                        if cur.rowcount == 0:
                            continue
                        cur.executemany(
                            "INSERT INTO events "
                            "(report_id, ts, host, category, severity, summary, data) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?)",
                            [(report_id, *event) for event in normalized_events],
                        )
                except sqlite3.Error as error:
                    print(f"Failed to store report {path.name}: {error}")
                    continue
            inserted_reports += 1
            inserted_events += total
    finally:
        conn.close()

    return {"reports": inserted_reports, "events": inserted_events}
