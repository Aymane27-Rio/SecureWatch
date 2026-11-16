import hmac
import json
import os
import re
from pathlib import Path

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader

app = FastAPI(title="SecureWatch API")

API_KEY = os.environ.get("WEBAPI_API_KEY", "")
LOG_DIR = Path(os.environ.get("SECUREWATCH_LOG_DIR", "/app/data/logs"))
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def check_api_key(token: str | None) -> bool:
    if not API_KEY or token is None:
        return False
    return hmac.compare_digest(token.encode("utf-8"), API_KEY.encode("utf-8"))


def require_api_key(token: str | None = Security(api_key_header)) -> None:
    if not check_api_key(token):
        raise HTTPException(status_code=401, detail="invalid api key")


protected_api = APIRouter(dependencies=[Depends(require_api_key)])


def parse_cors_origins(value: str) -> list[str]:
    origins = [origin.strip() for origin in value.split(",") if origin.strip()]
    if "*" in origins:
        raise ValueError("SECUREWATCH_CORS_ORIGINS must contain explicit origins")
    return origins


cors_origins = parse_cors_origins(os.environ.get("SECUREWATCH_CORS_ORIGINS", ""))
if cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_methods=["GET"],
        allow_headers=["X-API-Key"],
    )


def latest_reports():
    logs_dir = LOG_DIR.resolve()
    reports = []
    for path in LOG_DIR.glob("events_*.json"):
        resolved_path = path.resolve()
        if resolved_path.parent == logs_dir and resolved_path.is_file():
            reports.append(resolved_path)
    return sorted(reports)


def load_events(path: Path) -> list[dict]:
    try:
        with path.open("r", encoding="utf-8") as report_file:
            events = json.load(report_file)
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(events, list) or any(
        not isinstance(event, dict) for event in events
    ):
        return []
    return events


@protected_api.get("/api/metrics")
def metrics():
    files = latest_reports()
    if not files:
        return {
            "total_events": 0,
            "by_severity": {},
            "by_category": {},
            "last_run": None,
        }

    path = files[-1]
    events = load_events(path)

    by_severity = {}
    by_category = {}
    for event in events:
        severity = str(event.get("severity", 0))
        category = event.get("category", "unknown")
        by_severity[severity] = by_severity.get(severity, 0) + 1
        by_category[category] = by_category.get(category, 0) + 1

    timestamp = Path(path).name.removeprefix("events_").removesuffix(".json")
    return {
        "total_events": len(events),
        "by_severity": by_severity,
        "by_category": by_category,
        "last_run": timestamp,
    }


@protected_api.get("/api/reports")
def list_reports():
    reports = []
    for path in latest_reports():
        events = load_events(path)

        by_severity = {}
        for event in events:
            severity = str(event.get("severity", 0))
            by_severity[severity] = by_severity.get(severity, 0) + 1

        timestamp = Path(path).name.removeprefix("events_").removesuffix(".json")
        reports.append(
            {
                "id": timestamp,
                "file": Path(path).name,
                "summary": {"total": len(events), "by_severity": by_severity},
            }
        )
    return reports


@protected_api.get("/api/reports/{report_id}")
def get_report(report_id: str):
    if not re.fullmatch(r"\d{8}_\d{6}", report_id):
        raise HTTPException(status_code=400, detail="invalid report id")

    path = (LOG_DIR / f"events_{report_id}.json").resolve()
    if path.parent != LOG_DIR.resolve() or not path.is_file():
        raise HTTPException(status_code=404, detail="report not found")

    try:
        with path.open("r", encoding="utf-8") as report_file:
            events = json.load(report_file)
    except (OSError, json.JSONDecodeError) as error:
        raise HTTPException(
            status_code=500, detail="report could not be read"
        ) from error
    if not isinstance(events, list) or any(
        not isinstance(event, dict) for event in events
    ):
        raise HTTPException(status_code=500, detail="report has an invalid shape")
    return events


app.include_router(protected_api)
