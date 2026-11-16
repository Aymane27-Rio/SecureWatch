#!/usr/bin/env python3
import glob
import json
import os
import time
from pathlib import Path

from prometheus_client import Gauge, start_http_server

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT = os.path.dirname(BASE)  # project root
LOG_DIR = os.path.join(ROOT, "data", "logs")

g_total = Gauge("securewatch_events_total", "Total events in last report")
g_by_sev = Gauge(
    "securewatch_events_severity", "Events by severity in last report", ["severity"]
)
g_by_cat = Gauge(
    "securewatch_events_category", "Events by category in last report", ["category"]
)
previous_severities = set()
previous_categories = set()


def latest_json():
    files = sorted(
        path
        for path in glob.glob(os.path.join(LOG_DIR, "events_*.json"))
        if not Path(path).is_symlink() and Path(path).is_file()
    )
    return files[-1] if files else None


def reset_metrics():
    global previous_severities, previous_categories

    g_total.set(0)
    for severity in previous_severities:
        g_by_sev.labels(severity=severity).set(0)
    for category in previous_categories:
        g_by_cat.labels(category=category).set(0)
    previous_severities = set()
    previous_categories = set()


def tick():
    global previous_severities, previous_categories

    path = latest_json()
    if not path:
        reset_metrics()
        return

    try:
        with open(path, "r", encoding="utf-8") as report_file:
            events = json.load(report_file)
    except (OSError, json.JSONDecodeError):
        reset_metrics()
        return

    if not isinstance(events, list) or any(
        not isinstance(event, dict) for event in events
    ):
        reset_metrics()
        return

    g_total.set(len(events))
    sev_counts = {}
    cat_counts = {}
    for event in events:
        sev = str(event.get("severity", 0))
        cat = str(event.get("category", "unknown"))
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
        cat_counts[cat] = cat_counts.get(cat, 0) + 1

    for severity in previous_severities - sev_counts.keys():
        g_by_sev.labels(severity=severity).set(0)
    for category in previous_categories - cat_counts.keys():
        g_by_cat.labels(category=category).set(0)
    for sev, c in sev_counts.items():
        g_by_sev.labels(severity=sev).set(c)
    for cat, c in cat_counts.items():
        g_by_cat.labels(category=cat).set(c)
    previous_severities = set(sev_counts)
    previous_categories = set(cat_counts)


if __name__ == "__main__":
    start_http_server(9109)
    while True:
        tick()
        time.sleep(15)
