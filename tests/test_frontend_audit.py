import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AUDIT_PATH = ROOT / "scripts" / "check_frontend_audit.py"
SPEC = importlib.util.spec_from_file_location("securewatch_frontend_audit", AUDIT_PATH)
frontend_audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(frontend_audit)


class FrontendAuditPolicyTests(unittest.TestCase):
    def setUp(self):
        self.manifest = {
            "dependencies": {"react": "^18.2.0", "react-dom": "^18.2.0"},
            "devDependencies": {"vite": "^6.4.4"},
        }
        self.audit_report = {
            "vulnerabilities": {
                "picomatch": {
                    "via": [
                        {
                            "url": frontend_audit.ADVISORY_URL,
                            "title": "known unpatched advisory",
                        }
                    ]
                },
                "fdir": {"via": ["picomatch"]},
                "tinyglobby": {"via": ["fdir", "picomatch"]},
                "vite": {"via": ["fdir", "picomatch", "tinyglobby"]},
            }
        }

    def test_allows_only_the_known_dev_tool_advisory(self):
        self.assertTrue(
            frontend_audit.validate_audit_report(self.audit_report, self.manifest, 1)
        )

    def test_accepts_a_clean_audit(self):
        self.assertFalse(
            frontend_audit.validate_audit_report(
                {"vulnerabilities": {}}, self.manifest, 0
            )
        )

    def test_rejects_a_different_advisory(self):
        self.audit_report["vulnerabilities"]["picomatch"]["via"][0][
            "url"
        ] = "https://github.com/advisories/GHSA-unknown"
        with self.assertRaisesRegex(ValueError, "unexpected advisory"):
            frontend_audit.validate_audit_report(self.audit_report, self.manifest, 1)

    def test_rejects_an_unexpected_vulnerable_package(self):
        self.audit_report["vulnerabilities"]["react"] = {"via": ["unknown"]}
        with self.assertRaisesRegex(ValueError, "unexpected vulnerable frontend"):
            frontend_audit.validate_audit_report(self.audit_report, self.manifest, 1)

    def test_rejects_vulnerable_runtime_dependencies(self):
        self.manifest["dependencies"]["vite"] = "^6.4.4"
        with self.assertRaisesRegex(ValueError, "runtime dependencies"):
            frontend_audit.validate_audit_report(self.audit_report, self.manifest, 1)

    def test_rejects_audit_errors_and_unexpected_exit_codes(self):
        with self.assertRaisesRegex(ValueError, "unexpected status"):
            frontend_audit.validate_audit_report(self.audit_report, self.manifest, 2)
        with self.assertRaisesRegex(ValueError, "npm audit failed"):
            frontend_audit.validate_audit_report(
                {"error": {"code": "ENOAUDIT"}}, self.manifest, 1
            )


if __name__ == "__main__":
    unittest.main()
