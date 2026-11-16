import asyncio
import json
import tempfile
import unittest
from pathlib import Path

try:
    from fastapi import BackgroundTasks, HTTPException
    from backend.app import main as legacy_api
    from webapi import main as api
except ModuleNotFoundError as error:
    if error.name != "fastapi":
        raise
    api = None
    legacy_api = None


def request_api(path, api_key=None, target_app=None):
    async def make_request():
        headers = [(b"host", b"testserver")]
        if api_key is not None:
            headers.append((b"x-api-key", api_key.encode("utf-8")))
        sent = []
        received_request = False

        async def receive():
            nonlocal received_request
            if not received_request:
                received_request = True
                return {"type": "http.request", "body": b"", "more_body": False}
            return {"type": "http.disconnect"}

        async def send(message):
            sent.append(message)

        scope = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": path,
            "raw_path": path.encode("ascii"),
            "query_string": b"",
            "root_path": "",
            "headers": headers,
            "client": ("testclient", 1234),
            "server": ("testserver", 80),
        }
        await (target_app or api.app)(scope, receive, send)
        response = next(
            message for message in sent if message["type"] == "http.response.start"
        )
        body = b"".join(
            message.get("body", b"")
            for message in sent
            if message["type"] == "http.response.body"
        )
        return response["status"], json.loads(body)

    return asyncio.run(make_request())


@unittest.skipIf(api is None, "FastAPI dependencies are installed in CI")
class WebApiTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_db_path = api.DB_PATH
        api.DB_PATH = str(Path(self.temp_dir.name) / "securewatch.db")

        conn = api.get_conn(api.DB_PATH)
        try:
            api.init_db(conn)
            conn.execute(
                "INSERT INTO reports (report_id, filename, ts, total, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    "20260101_000000",
                    "events_20260101_000000.json",
                    "20260101_000000",
                    2,
                    "now",
                ),
            )
            conn.executemany(
                "INSERT INTO events (report_id, ts, host, category, severity, summary, data) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        "20260101_000000",
                        "2026-01-01T00:00:00Z",
                        "host",
                        "auth",
                        2,
                        "failed login",
                        "{}",
                    ),
                    (
                        "20260101_000000",
                        "2026-01-01T00:01:00Z",
                        "host",
                        "network",
                        1,
                        "port open",
                        "{}",
                    ),
                ],
            )
            conn.commit()
        finally:
            conn.close()

    def tearDown(self):
        api.DB_PATH = self.original_db_path
        self.temp_dir.cleanup()

    def test_metrics_and_event_filters_use_stored_data(self):
        metrics = api.metrics()
        filtered = api.query_events(severity=2, category="auth", limit=10, offset=0)

        self.assertEqual(metrics["total_events"], 2)
        self.assertEqual(metrics["by_severity"], {1: 1, 2: 1})
        self.assertEqual(filtered["count"], 1)
        self.assertEqual(filtered["events"][0]["summary"], "failed login")

    def test_read_routes_require_api_key_and_document_it(self):
        original_api_key = api.API_KEY
        api.API_KEY = "test-secret"
        try:
            missing_key = request_api("/reports")
            wrong_key = request_api("/reports", "wrong-key")
            valid_key = request_api("/reports", "test-secret")
            public_health = request_api("/hello")
            schema = api.app.openapi()
        finally:
            api.API_KEY = original_api_key

        self.assertEqual(missing_key[0], 401)
        self.assertEqual(wrong_key[0], 401)
        self.assertEqual(valid_key[0], 200)
        self.assertEqual(public_health[0], 200)
        self.assertIn("security", schema["paths"]["/reports"]["get"])

    def test_write_routes_require_a_configured_matching_key(self):
        original_api_key = api.API_KEY
        api.API_KEY = "test-secret"
        try:
            with self.assertRaises(HTTPException) as error:
                api.manual_ingest(BackgroundTasks(), x_api_key=None)
            self.assertEqual(error.exception.status_code, 401)
            self.assertTrue(api.check_api_key("test-secret"))
            self.assertFalse(api.check_api_key("wrong-key"))
        finally:
            api.API_KEY = original_api_key

    def test_scan_route_is_disabled_by_default(self):
        original_api_key = api.API_KEY
        original_allow_scan = api.ALLOW_SCAN
        api.API_KEY = "test-secret"
        api.ALLOW_SCAN = False
        try:
            with self.assertRaises(HTTPException) as error:
                api.trigger_scan("test-secret")
            self.assertEqual(error.exception.status_code, 403)
        finally:
            api.API_KEY = original_api_key
            api.ALLOW_SCAN = original_allow_scan


@unittest.skipIf(legacy_api is None, "FastAPI dependencies are installed in CI")
class LegacyApiSecurityTests(unittest.TestCase):
    def test_alternate_backend_cors_requires_explicit_origins(self):
        self.assertEqual(
            legacy_api.parse_cors_origins(
                "https://dashboard.example, http://localhost"
            ),
            ["https://dashboard.example", "http://localhost"],
        )
        with self.assertRaises(ValueError):
            legacy_api.parse_cors_origins("*")

    def test_alternate_backend_requires_key_and_rejects_invalid_report_ids(self):
        original_api_key = legacy_api.API_KEY
        original_log_dir = legacy_api.LOG_DIR
        with tempfile.TemporaryDirectory() as temp_dir:
            logs_dir = Path(temp_dir) / "logs"
            logs_dir.mkdir()
            outside_report = Path(temp_dir) / "outside.json"
            outside_report.write_text('[{"summary":"private"}]', encoding="utf-8")
            (logs_dir / "events_20260101_000000.json").symlink_to(outside_report)
            (logs_dir / "events_20260102_000000.json").write_text(
                '{"unexpected":"object"}', encoding="utf-8"
            )
            legacy_api.API_KEY = "test-secret"
            legacy_api.LOG_DIR = logs_dir
            try:
                missing_key = request_api("/api/metrics", target_app=legacy_api.app)
                valid_key = request_api(
                    "/api/metrics", "test-secret", target_app=legacy_api.app
                )
                reports = request_api(
                    "/api/reports", "test-secret", target_app=legacy_api.app
                )
                symlink_report = request_api(
                    "/api/reports/20260101_000000",
                    "test-secret",
                    target_app=legacy_api.app,
                )
                invalid_shape = request_api(
                    "/api/reports/20260102_000000",
                    "test-secret",
                    target_app=legacy_api.app,
                )
                invalid_report_id = request_api(
                    "/api/reports/not-a-timestamp",
                    "test-secret",
                    target_app=legacy_api.app,
                )
            finally:
                legacy_api.API_KEY = original_api_key
                legacy_api.LOG_DIR = original_log_dir

        self.assertEqual(missing_key[0], 401)
        self.assertEqual(valid_key[0], 200)
        self.assertEqual(valid_key[1]["total_events"], 0)
        self.assertEqual(reports[0], 200)
        self.assertEqual(symlink_report[0], 404)
        self.assertEqual(invalid_shape[0], 500)
        self.assertEqual(invalid_report_id[0], 400)


if __name__ == "__main__":
    unittest.main()
