#!/bin/sh
set -eu

api_key="${WEBAPI_API_KEY:-}"
case "$api_key" in
  ''|*[!0-9a-f]*)
    echo "WEBAPI_API_KEY must be 64 lowercase hexadecimal characters." >&2
    exit 1
    ;;
esac

if [ "${#api_key}" -ne 64 ]; then
  echo "WEBAPI_API_KEY must be 64 lowercase hexadecimal characters." >&2
  exit 1
fi
