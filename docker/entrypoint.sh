#!/bin/sh
set -eu

if [ "$#" -gt 0 ]; then
    exec "$@"
fi

DATA_DIR="${VEEN_DATA_DIR:-/var/lib/veen}"
LISTEN="${VEEN_LISTEN:-0.0.0.0:37411}"
CONFIG_PATH="${VEEN_CONFIG_PATH:-}"
PROFILE_ID="${VEEN_PROFILE_ID:-}"
LOG_LEVEL="${VEEN_LOG_LEVEL:-}"

umask 077
mkdir -p "$DATA_DIR"

set -- veen hub start --listen "$LISTEN" --data-dir "$DATA_DIR" --foreground

if [ -n "$CONFIG_PATH" ]; then
    set -- "$@" --config "$CONFIG_PATH"
fi

if [ -n "$PROFILE_ID" ]; then
    set -- "$@" --profile-id "$PROFILE_ID"
fi

if [ -n "$LOG_LEVEL" ]; then
    set -- "$@" --log-level "$LOG_LEVEL"
    if [ -z "${RUST_LOG:-}" ]; then
        export RUST_LOG="veen_hub=$LOG_LEVEL"
    fi
fi

exec "$@"
