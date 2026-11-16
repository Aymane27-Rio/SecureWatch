import datetime
import json
import sqlite3
from pathlib import Path

from .db import get_conn, init_db
from python.report_io import MAX_REPORT_BYTES, read_report, validate_events


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
                normalized_events = validate_events(
                    read_report(path, max_bytes=MAX_REPORT_BYTES)
                )
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
                            [
                                (
                                    report_id,
                                    event.get("ts"),
                                    event.get("host"),
                                    event.get("category"),
                                    event["severity"],
                                    event.get("summary"),
                                    json.dumps(event["data"], allow_nan=False),
                                )
                                for event in normalized_events
                            ],
                        )
                except sqlite3.Error as error:
                    print(f"Failed to store report {path.name}: {error}")
                    continue
            inserted_reports += 1
            inserted_events += total
    finally:
        conn.close()

    return {"reports": inserted_reports, "events": inserted_events}
