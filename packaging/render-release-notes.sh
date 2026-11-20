#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 VERSION OUTPUT_FILE" >&2
  exit 2
fi

version="$1"
output_file="$2"
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "Invalid release version: $version" >&2
  exit 2
fi

rpm_release=1
rpm_version="$version"
release_channel="stable release"
if [[ "$version" == *-* ]]; then
  prerelease="${version#*-}"
  rpm_version="${version%%-*}"
  rpm_release="0.${prerelease//-/.}"
  release_channel="pre-release"
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
temporary_file="${output_file}.tmp.$$"
trap 'rm -f -- "$temporary_file"' EXIT
sed -e "s/@VERSION@/$version/g" \
  -e "s/@RPM_VERSION@/$rpm_version/g" \
  -e "s/@RPM_RELEASE@/$rpm_release/g" \
  -e "s/@RELEASE_CHANNEL@/$release_channel/g" \
  "$root/packaging/release-notes.md" > "$temporary_file"

if grep -Eq '@(VERSION|RPM_VERSION|RPM_RELEASE|RELEASE_CHANNEL)@' "$temporary_file"; then
  echo "Release notes contain an unresolved template placeholder." >&2
  exit 1
fi

mv -f -- "$temporary_file" "$output_file"
