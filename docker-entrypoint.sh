#!/bin/sh
set -eu

PROJECTS_PATH="${PROJECTS_DIR:-/app/projects}"
DATA_PATH="${DATA_DIR:-/app/data}"
LOGS_PATH="${LOGS_DIR:-/app/logs}"

mkdir -p "$PROJECTS_PATH" "$DATA_PATH" "$LOGS_PATH"

if [ "$(id -u)" = "0" ]; then
    chown -R appuser:appuser "$PROJECTS_PATH" "$DATA_PATH" "$LOGS_PATH"
    exec runuser -u appuser -- "$@"
fi

exec "$@"

