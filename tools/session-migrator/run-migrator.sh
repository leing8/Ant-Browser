#!/usr/bin/env bash
# Launch ant-session-migrator on macOS (auto-builds standalone pure-Go binary if missing;
# enters interactive Chinese menu when invoked with no arguments, or forwards all CLI args).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY_PATH="$SCRIPT_DIR/ant-session-migrator"
FORCE_REBUILD="${MIGRATOR_REBUILD:-0}"

ensure_macos() {
  if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "[ERROR] run-migrator.sh is intended for macOS (Darwin)." >&2
    echo "        On Windows, use run-migrator.bat instead." >&2
    exit 1
  fi
}

build_binary() {
  if ! command -v go >/dev/null 2>&1; then
    echo "[ERROR] Go not found and prebuilt binary is missing: $BINARY_PATH" >&2
    echo "        Install Go, or copy a prebuilt ant-session-migrator binary into: $SCRIPT_DIR" >&2
    exit 1
  fi

  local goproxy="${DEV_GOPROXY:-${GOPROXY:-https://goproxy.cn,direct}}"
  echo "[1/2] Building ant-session-migrator for macOS ($(uname -m), pure Go, CGO_ENABLED=0)..."
  (
    cd "$SCRIPT_DIR"
    GOPROXY="$goproxy" CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$BINARY_PATH" .
  )
  chmod +x "$BINARY_PATH"
  echo "[2/2] [OK] Build succeeded: $BINARY_PATH"
  echo
}

ensure_macos

if [[ "$FORCE_REBUILD" == "1" || ! -f "$BINARY_PATH" ]]; then
  if [[ "$FORCE_REBUILD" == "1" ]]; then
    echo "[INFO] MIGRATOR_REBUILD=1 set. Rebuilding standalone macOS binary..."
  else
    echo "[INFO] ant-session-migrator not found. Building standalone macOS binary first..."
  fi
  build_binary
else
  # Strip quarantine attribute and ensure execute bit if a prebuilt binary was copied here.
  xattr -dr com.apple.quarantine "$BINARY_PATH" >/dev/null 2>&1 || true
  if [[ ! -x "$BINARY_PATH" ]]; then
    chmod +x "$BINARY_PATH"
  fi
fi

# Preserve the caller's working directory so relative paths (--app-root / --in / --out) resolve intuitively.
exec "$BINARY_PATH" "$@"
