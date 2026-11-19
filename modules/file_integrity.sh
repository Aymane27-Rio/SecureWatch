#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
baseline="${INTEGRITY_BASELINE:-$ROOT/data/state/integrity-baseline.json}"
exec python3 "$ROOT/python/file_integrity.py" verify --baseline "$baseline"
