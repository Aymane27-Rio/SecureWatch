import tempfile
import unittest
from pathlib import Path

try:
    from fastapi import BackgroundTasks, HTTPException
    from webapi import main as api
except ModuleNotFoundError as error:
    if error.name != "fastapi":
        raise
    api = None


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


if __name__ == "__main__":
    unittest.main()
