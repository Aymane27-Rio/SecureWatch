import datetime
import json
import os
import stat
from pathlib import Path

from .db import get_conn, init_db

MAX_REPORT_BYTES = int(os.environ.get("WEBAPI_MAX_REPORT_BYTES", 10 * 1024 * 1024))
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


def ingest_reports_from_dir(logs_dir="/app/data/logs", db_path=None, dry_run=False):
    logs_dir = Path(logs_dir)
    conn = get_conn(db_path)
    init_db(conn)
    cur = conn.cursor()

    inserted_reports = 0
    inserted_events = 0

    for path in sorted(logs_dir.glob("events_*.json")):
        if path.is_symlink() or not path.is_file():
            continue

        report_id = path.name.removeprefix("events_").removesuffix(".json")
        # skip if report already ingested
        cur.execute("SELECT 1 FROM reports WHERE report_id=? LIMIT 1", (report_id,))
        if cur.fetchone():
            continue

        try:
            events = _load_report(path)
        except (OSError, UnicodeDecodeError, ValueError) as e:
            print(f"Failed to read {path}: {e}")
            continue

        if not isinstance(events, list) or any(
            not isinstance(event, dict) for event in events
        ):
            print(f"Invalid report data in {path}: expected a list of event objects")
            continue

        total = len(events)
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        if not dry_run:
            cur.execute(
                "INSERT INTO reports (report_id, filename, ts, total, created_at) VALUES (?, ?, ?, ?, ?)",
                (report_id, path.name, report_id, total, now),
            )
            for e in events:
                cur.execute(
                    "INSERT INTO events (report_id, ts, host, category, severity, summary, data) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        report_id,
                        e.get("ts"),
                        e.get("host"),
                        e.get("category"),
                        int(e.get("severity", 0)),
                        e.get("summary"),
                        json.dumps(e.get("data", {})),
                    ),
                )
            conn.commit()
        inserted_reports += 1
        inserted_events += total

    conn.close()
    return {"reports": inserted_reports, "events": inserted_events}
