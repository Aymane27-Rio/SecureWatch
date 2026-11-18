#!/usr/bin/env python3
"""Keep the frontend audit strict except for one unpatched dev-tool advisory."""

import argparse
import json
from pathlib import Path

ADVISORY_ID = "GHSA-fc5q-39xc-vjpf"
ADVISORY_URL = f"https://github.com/advisories/{ADVISORY_ID}"
ALLOWED_PACKAGES = frozenset({"fdir", "picomatch", "tinyglobby", "vite"})


def validate_audit_report(report, manifest, audit_exit_code):
    if audit_exit_code not in (0, 1):
        raise ValueError(f"npm audit exited with unexpected status {audit_exit_code}")
    if not isinstance(report, dict):
        raise ValueError("npm audit did not return a JSON object")
    if report.get("error"):
        raise ValueError(f"npm audit failed: {report['error']}")

    vulnerabilities = report.get("vulnerabilities", {})
    if not isinstance(vulnerabilities, dict):
        raise ValueError("npm audit returned an invalid vulnerabilities field")
    if not vulnerabilities:
        if audit_exit_code != 0:
            raise ValueError("npm audit failed without reporting a vulnerability")
        return False
    if audit_exit_code == 0:
        raise ValueError("npm audit reported vulnerabilities but exited successfully")

    unexpected_packages = set(vulnerabilities) - ALLOWED_PACKAGES
    if unexpected_packages:
        packages = ", ".join(sorted(unexpected_packages))
        raise ValueError(f"unexpected vulnerable frontend packages: {packages}")

    runtime_dependencies = set(manifest.get("dependencies", {}))
    runtime_findings = set(vulnerabilities) & runtime_dependencies
    if runtime_findings:
        packages = ", ".join(sorted(runtime_findings))
        raise ValueError(f"vulnerabilities affect runtime dependencies: {packages}")

    advisory_found = False
    for package, finding in vulnerabilities.items():
        if not isinstance(finding, dict) or not isinstance(finding.get("via"), list):
            raise ValueError(f"invalid npm audit entry for {package}")
        for source in finding["via"]:
            if isinstance(source, dict):
                if source.get("url") != ADVISORY_URL:
                    raise ValueError(f"unexpected advisory affecting {package}")
                advisory_found = True
            elif isinstance(source, str):
                if source not in ALLOWED_PACKAGES:
                    raise ValueError(
                        f"unexpected dependency advisory affecting {package}"
                    )
            else:
                raise ValueError(f"invalid advisory source for {package}")

    if not advisory_found:
        raise ValueError(f"the only allowed advisory must be {ADVISORY_ID}")
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("audit_report", type=Path)
    parser.add_argument("package_manifest", type=Path)
    parser.add_argument("npm_exit_code", type=int)
    args = parser.parse_args(argv)

    try:
        report = json.loads(args.audit_report.read_text(encoding="utf-8"))
        manifest = json.loads(args.package_manifest.read_text(encoding="utf-8"))
        allowed_advisory = validate_audit_report(report, manifest, args.npm_exit_code)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        parser.exit(1, f"frontend audit policy failed: {error}\n")

    if allowed_advisory:
        print(
            "::warning::Allowing the known unpatched dev-tool advisory "
            f"{ADVISORY_ID}; production dependency audit passed. See {ADVISORY_URL}"
        )
    else:
        print("Frontend audit passed with no vulnerabilities.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
