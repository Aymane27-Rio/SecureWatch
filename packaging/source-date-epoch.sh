securewatch_set_source_date_epoch() {
  if [[ -z "${SOURCE_DATE_EPOCH:-}" ]]; then
    if command -v git >/dev/null 2>&1; then
      SOURCE_DATE_EPOCH="$(git -C "$1" log -1 --format=%ct 2>/dev/null || true)"
    fi
    SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}"
  fi
  export SOURCE_DATE_EPOCH
}
