#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 VERSION OUTPUT_DIRECTORY" >&2
  exit 2
fi

version="$1"
output_dir="$2"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$root/packaging/source-date-epoch.sh"
securewatch_set_source_date_epoch "$root"
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "Invalid version: $version" >&2
  exit 2
fi

rpm_version="${version%%-*}"
if [[ "$version" == *-* ]]; then
  prerelease="${version#*-}"
  rpm_release="0.${prerelease//-/.}"
else
  rpm_release=1
fi

work_dir="$(mktemp -d)"
trap 'rm -rf -- "$work_dir"' EXIT
mkdir -p "$output_dir" "$work_dir/rpmbuild/SOURCES/payload"
bash "$root/packaging/stage-package.sh" "$version" "$work_dir/payload"
cp -a "$work_dir/payload/." "$work_dir/rpmbuild/SOURCES/payload/"

rpmbuild -bb "$root/packaging/securewatch.spec" \
  --define "_topdir $work_dir/rpmbuild" \
  --define "_rpmdir $work_dir/rpmbuild/RPMS" \
  --define "source_date_epoch_from_changelog 0" \
  --define "use_source_date_epoch_as_buildtime 1" \
  --define "build_mtime_policy clamp_to_source_date_epoch" \
  --define "_buildtime $SOURCE_DATE_EPOCH" \
  --define "_buildhost reproducible" \
  --define "securewatch_version $rpm_version" \
  --define "securewatch_release $rpm_release" \
  --define "securewatch_payload $work_dir/rpmbuild/SOURCES/payload"

find "$work_dir/rpmbuild/RPMS" -type f -name 'securewatch-*.rpm' \
  -exec cp -- '{}' "$output_dir/" \;
