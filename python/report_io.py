"""Bounded, symlink-safe loading and validation for generated scan reports."""

import json
import os
import stat

MAX_REPORT_BYTES = int(os.environ.get("WEBAPI_MAX_REPORT_BYTES", 10 * 1024 * 1024))
MAX_REPORT_EVENTS = 100_000

if MAX_REPORT_BYTES < 1:
    raise RuntimeError("WEBAPI_MAX_REPORT_BYTES must be a positive integer")


def read_report(path, max_bytes=MAX_REPORT_BYTES):
    """Load a regular report file without following symlinks or exceeding its byte cap."""
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
        if metadata.st_size > max_bytes:
            raise ValueError("report exceeds WEBAPI_MAX_REPORT_BYTES")

        payload = report_file.read(max_bytes + 1)
        if len(payload) > max_bytes:
            raise ValueError("report exceeds WEBAPI_MAX_REPORT_BYTES")

    return json.loads(payload.decode("utf-8"))


def validate_events(events, max_events=MAX_REPORT_EVENTS):
    """Validate report event fields and normalize values for database and metrics use."""
    if not isinstance(events, list):
        raise ValueError("expected a list of event objects")
    if len(events) > max_events:
        raise ValueError(f"report exceeds the {max_events}-event limit")

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

        normalized_event = dict(event)
        normalized_event["severity"] = severity
        normalized_event["data"] = event.get("data", {})
        json.dumps(normalized_event["data"], allow_nan=False)
        normalized.append(normalized_event)
    return normalized
