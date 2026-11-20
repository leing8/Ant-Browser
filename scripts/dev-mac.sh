#!/usr/bin/env bash

# Ant Browser macOS 外部开发启动器（零耦合主程序源码，行为对齐 bat/dev.bat）。
#
# 核心原理：
#   macOS 下直接运行 `wails dev` 会打包为 build/bin/Ant Browser.app/Contents/MacOS/ant-chrome，
#   导致 main.go 的 `/build/bin` 后缀判断未命中而回退为生产态，并由 apppath 分离到
#   ~/Library/Application Support/ant-browser。
#   本脚本在不修改 main.go 与任何业务代码的前提下，直接使用与 Wails dev 一致的 `-tags dev`
#   编译为裸可执行文件 build/bin/ant-chrome-dev，并在项目根目录注入 Wails dev 运行时环境变量，
#   从而自然命中 main.go 的 dev 模式判断，使 config.yaml、data/、chrome/ 全部落在项目目录。

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEV_BINARY="$ROOT_DIR/build/bin/ant-chrome-dev"
DEV_MODE="stable"
SHOW_USAGE=0
SKIP_BINDINGS=0
CLEAN_BUILD=0
FORCE_NPM_INSTALL=0
DEBUG_STARTUP=0

PREFERRED_FRONTEND_PORT="${PREFERRED_FRONTEND_PORT:-5218}"
FRONTEND_PORT=""
WAILS_DEVSERVER_ADDRESS=""
WAILS_LOG_LEVEL="${WAILS_LOG_LEVEL:-Info}"
WATCHER_PID=""
WATCHER_STARTED=0
APP_PID=""
TEMP_PLACEHOLDER_CREATED=0
TEMP_DIST_CREATED=0

print_usage() {
  cat <<'EOF'
Usage:
  ./scripts/dev-mac.sh [stable|live|limited] [options]

Modes:
  stable            Default. Build frontend static assets and launch build/bin/ant-chrome-dev
                    against project-root data/ & chrome/ (matches bat\dev.bat).
  live              Start frontend Vite watcher (dev-watcher.mjs) and connect build/bin/ant-chrome-dev
                    to the live frontend dev server.
  limited           Same as live, with stricter Node heap and RSS hard-limit controls.
  help              Show this help.

Options:
  --skip-bindings   Skip regenerating Wails bindings (faster startup when Go APIs didn't change).
  --clean           Force clean frontend/dist before building in stable mode (npm run build:clean).
  --install         Force running npm install in frontend/.
  --debug           Enable ANT_BROWSER_DEBUG_STARTUP=1 verbose startup logs.
  -h, --help        Show this help.

Environment variables:
  DEV_PROXY_URL            HTTP(S) proxy for npm / Node / Go downloads.
  DEV_NO_PROXY             NO_PROXY value.
  DEV_GOPROXY              Override GOPROXY (default: https://goproxy.cn,direct when GOPROXY is unset).
  PREFERRED_FRONTEND_PORT  Preferred Vite port in live/limited mode (default: 5218).
  WAILS_DEVSERVER_PORT     Starting port for Wails devserver (default: 34115).
  WAILS_LOG_LEVEL          Wails runtime log level (default: Info).

Examples:
  ./scripts/dev-mac.sh
  ./scripts/dev-mac.sh stable --skip-bindings
  ./scripts/dev-mac.sh live
  ./scripts/dev-mac.sh limited --debug
EOF
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      stable|live|limited)
        DEV_MODE="$1"
        shift
        ;;
      help|-h|--help)
        SHOW_USAGE=1
        shift
        ;;
      --skip-bindings)
        SKIP_BINDINGS=1
        shift
        ;;
      --clean)
        CLEAN_BUILD=1
        shift
        ;;
      --install)
        FORCE_NPM_INSTALL=1
        shift
        ;;
      --debug)
        DEBUG_STARTUP=1
        shift
        ;;
      *)
        echo "[ERROR] Unsupported argument: $1" >&2
        echo >&2
        print_usage >&2
        exit 1
        ;;
    esac
  done
}

ensure_macos() {
  if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "[ERROR] scripts/dev-mac.sh is intended for macOS (Darwin)." >&2
    echo "        Use scripts/dev.sh on Linux or bat\\dev.bat on Windows." >&2
    exit 1
  fi

  local raw_arch
  raw_arch="$(uname -m)"
  case "$raw_arch" in
    arm64) HOST_ARCH="arm64" ;;
    x86_64) HOST_ARCH="amd64" ;;
    *)
      echo "[ERROR] Unsupported macOS architecture: $raw_arch" >&2
      exit 1
      ;;
  esac
}

prepend_path_if_dir() {
  local dir="$1"
  if [[ -n "$dir" && -d "$dir" && ":$PATH:" != *":$dir:"* ]]; then
    PATH="$dir:$PATH"
    export PATH
  fi
}

setup_go_bin_path() {
  if command -v go >/dev/null 2>&1; then
    local gobin gopath
    gobin="$(go env GOBIN 2>/dev/null || true)"
    gopath="$(go env GOPATH 2>/dev/null || true)"
    prepend_path_if_dir "$gobin"
    if [[ -n "$gopath" ]]; then
      prepend_path_if_dir "$gopath/bin"
    fi
  fi
  prepend_path_if_dir "$HOME/go/bin"
}

require_cmd() {
  local cmd="$1"
  local hint="${2:-}"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "[ERROR] Missing required command: $cmd" >&2
    if [[ -n "$hint" ]]; then
      echo "        $hint" >&2
    fi
    exit 1
  fi
}

apply_proxy_settings() {
  if [[ -n "${DEV_PROXY_URL:-}" ]]; then
    export HTTP_PROXY="$DEV_PROXY_URL"
    export HTTPS_PROXY="$DEV_PROXY_URL"
    export http_proxy="$DEV_PROXY_URL"
    export https_proxy="$DEV_PROXY_URL"
  fi

  if [[ -n "${DEV_NO_PROXY:-}" ]]; then
    export NO_PROXY="$DEV_NO_PROXY"
    export no_proxy="$DEV_NO_PROXY"
  fi

  if [[ -n "${DEV_GOPROXY:-}" ]]; then
    export GOPROXY="$DEV_GOPROXY"
  elif [[ -z "${GOPROXY:-}" ]]; then
    export GOPROXY="https://goproxy.cn,direct"
  fi
}

print_proxy_settings() {
  if [[ -n "${DEV_PROXY_URL:-}" ]]; then
    echo "HTTP/HTTPS proxy: $DEV_PROXY_URL"
  else
    echo "HTTP/HTTPS proxy: disabled"
  fi
  if [[ -n "${DEV_NO_PROXY:-}" ]]; then
    echo "NO_PROXY: $DEV_NO_PROXY"
  fi
  echo "Go proxy: ${GOPROXY:-default}"
  echo
}

is_tcp_port_busy() {
  local port="$1"
  lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1
}

resolve_wails_devserver() {
  local start_port="${WAILS_DEVSERVER_PORT:-34115}"
  local host="${WAILS_DEVSERVER_HOST:-127.0.0.1}"
  local port="$start_port"
  local max_port=$((start_port + 50))

  while is_tcp_port_busy "$port"; do
    port=$((port + 1))
    if [[ "$port" -gt "$max_port" ]]; then
      echo "[ERROR] Failed to find a free Wails devserver port in range $start_port-$max_port." >&2
      exit 1
    fi
  done

  WAILS_DEVSERVER_ADDRESS="$host:$port"
  export WAILS_DEVSERVER_ADDRESS
}

resolve_frontend_dev_port() {
  local start_port="$PREFERRED_FRONTEND_PORT"
  local port="$start_port"
  local max_port=$((start_port + 20))

  echo "Resolving frontend dev port..."
  while is_tcp_port_busy "$port"; do
    echo "[dev] port $port is occupied, trying next port..."
    port=$((port + 1))
    if [[ "$port" -gt "$max_port" ]]; then
      echo "[ERROR] Failed to find a free frontend dev port in range $start_port-$max_port." >&2
      exit 1
    fi
  done

  FRONTEND_PORT="$port"
  export FRONTEND_PORT
  echo "[OK] Frontend dev port: $FRONTEND_PORT"
  echo
}

cleanup_dev_logs() {
  local f
  for f in \
    "tmp-npm-dev.err.log" \
    "tmp-npm-dev.log" \
    "tmp-frontend-limited-watcher.pid" \
    "tmp-wails-err.log" \
    "tmp-wails-out.log" \
    "tmp-wails2-err.log" \
    "tmp-wails2-out.log" \
    "tmp-wails3-err.log" \
    "tmp-wails3-out.log" \
    "tmp-wails.err" \
    "wails-dev-capture.log" \
    "wails-dev-run.log" \
    "wails-dev-stderr.log" \
    "wails-dev-stdout.log"
  do
    if [[ -f "$ROOT_DIR/$f" ]]; then
      rm -f "$ROOT_DIR/$f" 2>/dev/null || true
    fi
  done
}

stop_matching_processes() {
  local pattern="$1"
  local pids
  pids="$(pgrep -f "$pattern" 2>/dev/null || true)"
  if [[ -z "$pids" ]]; then
    return 0
  fi

  local pid
  for pid in $pids; do
    if [[ "$pid" == "$$" ]]; then
      continue
    fi
    kill "$pid" 2>/dev/null || true
  done

  local i
  for i in 1 2 3 4 5; do
    pids="$(pgrep -f "$pattern" 2>/dev/null || true)"
    if [[ -z "$pids" ]]; then
      return 0
    fi
    sleep 0.2
  done

  for pid in $pids; do
    if [[ "$pid" == "$$" ]]; then
      continue
    fi
    kill -9 "$pid" 2>/dev/null || true
  done
}

cleanup_app_processes() {
  echo "Cleaning stale app processes..."
  stop_matching_processes "$ROOT_DIR/build/bin/ant-chrome-dev"
  stop_matching_processes "$ROOT_DIR/build/bin/Ant Browser.app/Contents/MacOS/ant-chrome"
  echo
}

cleanup_frontend_dev_processes() {
  echo "Cleaning stale frontend dev processes..."
  stop_matching_processes "$ROOT_DIR/frontend/scripts/dev-watcher.mjs"
  stop_matching_processes "$ROOT_DIR/frontend/node_modules/vite/bin/vite.js"
  echo
}

cleanup_dev_binary() {
  echo "Removing stale dev binary..."
  if [[ -f "$DEV_BINARY" ]]; then
    rm -f "$DEV_BINARY"
  fi
  if [[ -d "$ROOT_DIR/build/bin/Ant Browser.app" ]]; then
    rm -rf "$ROOT_DIR/build/bin/Ant Browser.app"
  fi
  echo
}

stage_proxy_runtimes() {
  local src_dir="$ROOT_DIR/bin/darwin-$HOST_ARCH"
  local cache_dir="$ROOT_DIR/.tmp/runtime-cache/darwin-$HOST_ARCH"

  if [[ ! -d "$src_dir" ]]; then
    echo "[WARN] Darwin proxy runtime directory not found: $src_dir"
    return 0
  fi

  mkdir -p "$cache_dir"

  local bin_name src_file dst_file
  for bin_name in xray sing-box; do
    src_file="$src_dir/$bin_name"
    dst_file="$cache_dir/$bin_name"
    if [[ ! -f "$src_file" ]]; then
      echo "[WARN] Missing proxy runtime binary: $src_file"
      continue
    fi
    if [[ ! -f "$dst_file" || "$src_file" -nt "$dst_file" ]] || ! cmp -s "$src_file" "$dst_file" 2>/dev/null; then
      cp "$src_file" "$dst_file"
    fi
    chmod +x "$dst_file"
  done

  if [[ -z "${XRAY_BINARY_PATH:-}" && -x "$cache_dir/xray" ]]; then
    export XRAY_BINARY_PATH="$cache_dir/xray"
  fi
  if [[ -z "${SINGBOX_BINARY_PATH:-}" && -x "$cache_dir/sing-box" ]]; then
    export SINGBOX_BINARY_PATH="$cache_dir/sing-box"
  fi

  echo "Proxy runtimes (darwin-$HOST_ARCH):"
  echo "  XRAY_BINARY_PATH   : ${XRAY_BINARY_PATH:-<not set>}"
  echo "  SINGBOX_BINARY_PATH: ${SINGBOX_BINARY_PATH:-<not set>}"
  echo
}

check_dependencies() {
  echo "Checking dependencies..."
  if [[ ! -f "$ROOT_DIR/go.mod" ]]; then
    echo "[ERROR] go.mod not found in repository root." >&2
    exit 1
  fi
  if [[ ! -f "$ROOT_DIR/wails.json" ]]; then
    echo "[ERROR] wails.json not found in repository root." >&2
    exit 1
  fi

  setup_go_bin_path
  require_cmd node "Install Node.js (e.g. via fnm/nvm/brew)."
  require_cmd npm "Install npm along with Node.js."
  require_cmd go "Install Go >= 1.22."
  require_cmd lsof "macOS built-in lsof is required for port checks."

  if [[ "$SKIP_BINDINGS" -ne 1 || ! -d "$ROOT_DIR/frontend/src/wailsjs" ]]; then
    require_cmd wails "Install Wails CLI: go install github.com/wailsapp/wails/v2/cmd/wails@v2.12.0 (or pass --skip-bindings)"
  fi
}

download_go_dependencies() {
  echo "Downloading Go dependencies..."
  (cd "$ROOT_DIR" && go mod download)
  echo
}

install_frontend_dependencies() {
  if [[ "$FORCE_NPM_INSTALL" -eq 1 || ! -d "$ROOT_DIR/frontend/node_modules" ]]; then
    echo "Installing frontend dependencies..."
    (cd "$ROOT_DIR/frontend" && npm install)
    echo
  fi
}

ensure_embed_dist() {
  if [[ ! -d "$ROOT_DIR/frontend/dist" ]]; then
    mkdir -p "$ROOT_DIR/frontend/dist"
    TEMP_DIST_CREATED=1
  fi
  if [[ -z "$(ls -A "$ROOT_DIR/frontend/dist" 2>/dev/null || true)" ]]; then
    printf 'placeholder\n' > "$ROOT_DIR/frontend/dist/__wails_placeholder__.txt"
    TEMP_PLACEHOLDER_CREATED=1
  fi
}

cleanup_embed_placeholder() {
  if [[ "$TEMP_PLACEHOLDER_CREATED" -eq 1 ]]; then
    rm -f "$ROOT_DIR/frontend/dist/__wails_placeholder__.txt" 2>/dev/null || true
    TEMP_PLACEHOLDER_CREATED=0
  fi
  if [[ "$TEMP_DIST_CREATED" -eq 1 ]]; then
    rmdir "$ROOT_DIR/frontend/dist" 2>/dev/null || true
    TEMP_DIST_CREATED=0
  fi
}

regenerate_bindings() {
  if [[ "$SKIP_BINDINGS" -eq 1 && -d "$ROOT_DIR/frontend/src/wailsjs" ]]; then
    echo "Skipping Wails bindings generation (--skip-bindings)."
    echo
    return 0
  fi

  echo "Regenerating Wails bindings..."
  ensure_embed_dist

  local gen_status=0
  (cd "$ROOT_DIR" && wails generate module) || gen_status=$?

  # Normalize runtime file permissions on macOS so git status stays clean (100644).
  if [[ -d "$ROOT_DIR/frontend/src/wailsjs/runtime" ]]; then
    chmod 644 "$ROOT_DIR"/frontend/src/wailsjs/runtime/* 2>/dev/null || true
  fi

  cleanup_embed_placeholder

  if [[ "$gen_status" -ne 0 ]]; then
    echo "[ERROR] Failed to regenerate Wails bindings." >&2
    exit "$gen_status"
  fi
  if [[ ! -d "$ROOT_DIR/frontend/src/wailsjs" ]]; then
    echo "[ERROR] Wails bindings output folder not found: frontend/src/wailsjs" >&2
    exit 1
  fi
  echo
}

prepare_tooling() {
  check_dependencies
  download_go_dependencies
  install_frontend_dependencies
  regenerate_bindings
}

build_frontend_assets() {
  echo "Building frontend static assets..."
  if [[ "$CLEAN_BUILD" -eq 1 ]]; then
    (cd "$ROOT_DIR/frontend" && npm run build:clean)
  else
    (cd "$ROOT_DIR/frontend" && npm run build)
  fi
  if [[ ! -f "$ROOT_DIR/frontend/dist/index.html" ]]; then
    echo "[ERROR] frontend/dist/index.html was not generated." >&2
    exit 1
  fi
  echo
}

build_dev_binary() {
  echo "Building macOS dev binary (build/bin/ant-chrome-dev)..."
  mkdir -p "$ROOT_DIR/build/bin"

  local cgo_ldflags="${CGO_LDFLAGS:-}"
  local macos_major=""
  macos_major="$(sw_vers -productVersion 2>/dev/null | cut -d. -f1 || true)"
  if [[ -z "$macos_major" || "$macos_major" -ge 11 ]]; then
    if [[ "$cgo_ldflags" != *"UniformTypeIdentifiers"* ]]; then
      cgo_ldflags="${cgo_ldflags:+$cgo_ldflags }-framework UniformTypeIdentifiers"
    fi
  fi

  (
    cd "$ROOT_DIR"
    CGO_ENABLED=1 \
      CGO_LDFLAGS="$cgo_ldflags" \
      go build -buildvcs=false -gcflags "all=-N -l" -tags dev -o "$DEV_BINARY" .
  )
  if [[ ! -x "$DEV_BINARY" ]]; then
    echo "[ERROR] Failed to build dev binary: $DEV_BINARY" >&2
    exit 1
  fi
  echo "[OK] Built: $DEV_BINARY"
  echo
}

cleanup_watcher() {
  if [[ -n "$WATCHER_PID" ]]; then
    if kill -0 "$WATCHER_PID" 2>/dev/null; then
      kill "$WATCHER_PID" 2>/dev/null || true
      local i
      for i in 1 2 3 4 5; do
        kill -0 "$WATCHER_PID" 2>/dev/null || break
        sleep 0.2
      done
      kill -9 "$WATCHER_PID" 2>/dev/null || true
    fi
    WATCHER_PID=""
  fi
  if [[ "$WATCHER_STARTED" -eq 1 ]]; then
    stop_matching_processes "$ROOT_DIR/frontend/node_modules/vite/bin/vite.js"
    WATCHER_STARTED=0
  fi
}

cleanup_app() {
  if [[ -n "$APP_PID" ]]; then
    if kill -0 "$APP_PID" 2>/dev/null; then
      kill "$APP_PID" 2>/dev/null || true
      local i
      for i in 1 2 3 4 5 6 7 8 9 10; do
        kill -0 "$APP_PID" 2>/dev/null || break
        sleep 0.2
      done
      kill -9 "$APP_PID" 2>/dev/null || true
    fi
    APP_PID=""
  fi
}

cleanup_on_exit() {
  cleanup_app
  cleanup_watcher
  cleanup_embed_placeholder
}

handle_signal() {
  cleanup_on_exit
  exit 0
}

start_watcher() {
  echo "Starting frontend watcher..."
  (
    cd "$ROOT_DIR"
    exec node "$ROOT_DIR/frontend/scripts/dev-watcher.mjs" \
      >"$ROOT_DIR/tmp-npm-dev.log" \
      2>"$ROOT_DIR/tmp-npm-dev.err.log"
  ) &
  WATCHER_PID="$!"
  WATCHER_STARTED=1
  echo "[OK] Frontend watcher PID: $WATCHER_PID"
  echo "Watcher logs: tmp-npm-dev.log / tmp-npm-dev.err.log"
  echo
}

wait_for_frontend_dev_server() {
  local timeout_sec=20
  local elapsed=0

  while [[ "$elapsed" -lt $((timeout_sec * 2)) ]]; do
    if is_tcp_port_busy "$FRONTEND_PORT"; then
      echo "[OK] Frontend dev server is listening on $FRONTEND_PORT."
      echo
      return 0
    fi
    if [[ -n "$WATCHER_PID" ]] && ! kill -0 "$WATCHER_PID" 2>/dev/null; then
      echo "[ERROR] Frontend watcher exited before the dev server became ready." >&2
      if [[ -f "$ROOT_DIR/tmp-npm-dev.err.log" ]]; then
        cat "$ROOT_DIR/tmp-npm-dev.err.log" >&2
      fi
      if [[ -f "$ROOT_DIR/tmp-npm-dev.log" ]]; then
        cat "$ROOT_DIR/tmp-npm-dev.log" >&2
      fi
      exit 1
    fi
    sleep 0.5
    elapsed=$((elapsed + 1))
  done

  echo "[ERROR] Timed out waiting for the frontend dev server on port $FRONTEND_PORT." >&2
  if [[ -f "$ROOT_DIR/tmp-npm-dev.err.log" ]]; then
    cat "$ROOT_DIR/tmp-npm-dev.err.log" >&2
  fi
  exit 1
}

launch_dev_binary() {
  local asset_dir="$1"
  local frontend_url="$2"

  if [[ "$DEBUG_STARTUP" -eq 1 ]]; then
    export ANT_BROWSER_DEBUG_STARTUP=1
  fi

  cd "$ROOT_DIR"
  loglevel="$WAILS_LOG_LEVEL" \
    assetdir="$asset_dir" \
    frontenddevserverurl="$frontend_url" \
    devserver="$WAILS_DEVSERVER_ADDRESS" \
    "$DEV_BINARY" &
  APP_PID="$!"

  local app_exit=0
  wait "$APP_PID" || app_exit=$?
  APP_PID=""

  if [[ "$app_exit" -ne 0 ]]; then
    echo
    echo "[ERROR] ant-chrome-dev exited with code $app_exit." >&2
  fi
  return "$app_exit"
}

run_stable() {
  echo "========================================"
  echo "  Ant Browser - macOS Dev Launcher"
  echo "========================================"
  echo
  echo "Current workdir: $ROOT_DIR"
  echo "Host arch      : darwin/$HOST_ARCH"
  echo "Mode           : stable"
  echo

  cleanup_dev_logs
  apply_proxy_settings

  echo "Frontend mode: stable static assets"
  if [[ "$CLEAN_BUILD" -eq 1 ]]; then
    echo "Frontend build: npm run build:clean"
  else
    echo "Frontend build: one-shot npm run build"
  fi
  echo "Wails frontend dev server: disabled"
  print_proxy_settings

  cleanup_app_processes
  cleanup_frontend_dev_processes
  cleanup_dev_binary
  prepare_tooling
  stage_proxy_runtimes
  build_frontend_assets
  build_dev_binary
  resolve_wails_devserver

  echo "Starting Ant Browser (dev mode in project root)..."
  echo "Binary          : $DEV_BINARY"
  echo "Asset source    : $ROOT_DIR/frontend/dist"
  echo "Wails dev server: http://$WAILS_DEVSERVER_ADDRESS"
  echo "App root & data : $ROOT_DIR (config.yaml / data/ / chrome/)"
  echo

  launch_dev_binary "frontend/dist" ""
}

run_live() {
  local limited_mode="$1"

  if [[ "$limited_mode" == "1" ]]; then
    export FRONTEND_NODE_MAX_OLD_SPACE_SIZE_MB="${FRONTEND_NODE_MAX_OLD_SPACE_SIZE_MB:-256}"
    export FRONTEND_NODE_RSS_WARN_MB="${FRONTEND_NODE_RSS_WARN_MB:-256}"
    export FRONTEND_NODE_RSS_HARD_LIMIT_MB="${FRONTEND_NODE_RSS_HARD_LIMIT_MB:-512}"
    export FRONTEND_NODE_RSS_AUTO_RESTART="${FRONTEND_NODE_RSS_AUTO_RESTART:-0}"
    export FRONTEND_NODE_RSS_RESTART_MAX_COUNT="${FRONTEND_NODE_RSS_RESTART_MAX_COUNT:-1}"
  else
    export FRONTEND_NODE_MAX_OLD_SPACE_SIZE_MB="${FRONTEND_NODE_MAX_OLD_SPACE_SIZE_MB:-512}"
    export FRONTEND_NODE_RSS_WARN_MB="${FRONTEND_NODE_RSS_WARN_MB:-384}"
    export FRONTEND_NODE_RSS_HARD_LIMIT_MB="${FRONTEND_NODE_RSS_HARD_LIMIT_MB:-0}"
    export FRONTEND_NODE_RSS_AUTO_RESTART="${FRONTEND_NODE_RSS_AUTO_RESTART:-1}"
    export FRONTEND_NODE_RSS_RESTART_MAX_COUNT="${FRONTEND_NODE_RSS_RESTART_MAX_COUNT:-3}"
  fi
  export FRONTEND_NODE_MAX_SEMI_SPACE_SIZE_MB="${FRONTEND_NODE_MAX_SEMI_SPACE_SIZE_MB:-16}"
  export FRONTEND_NODE_RSS_HARD_LIMIT_HITS="${FRONTEND_NODE_RSS_HARD_LIMIT_HITS:-3}"
  export FRONTEND_NODE_RSS_RESTART_DELAY_MS="${FRONTEND_NODE_RSS_RESTART_DELAY_MS:-1500}"
  export FRONTEND_NODE_RSS_RESTART_WINDOW_MS="${FRONTEND_NODE_RSS_RESTART_WINDOW_MS:-300000}"
  export FRONTEND_NODE_MEMORY_POLL_MS="${FRONTEND_NODE_MEMORY_POLL_MS:-3000}"
  export FRONTEND_DISABLE_HMR="${FRONTEND_DISABLE_HMR:-0}"

  echo "========================================"
  echo "  Ant Browser - macOS Dev Launcher"
  echo "========================================"
  echo
  echo "Current workdir: $ROOT_DIR"
  echo "Host arch      : darwin/$HOST_ARCH"
  if [[ "$limited_mode" == "1" ]]; then
    echo "Mode           : limited"
  else
    echo "Mode           : live"
  fi
  echo

  cleanup_dev_logs
  apply_proxy_settings

  if [[ "$limited_mode" == "1" ]]; then
    echo "Frontend mode: live dev server with RSS hard limit"
  else
    echo "Frontend mode: live dev server"
  fi
  echo "Preferred frontend port        : $PREFERRED_FRONTEND_PORT"
  echo "Frontend Node old-space limit  : $FRONTEND_NODE_MAX_OLD_SPACE_SIZE_MB MB"
  echo "Frontend Node semi-space limit : $FRONTEND_NODE_MAX_SEMI_SPACE_SIZE_MB MB"
  echo "Frontend Node RSS warning      : $FRONTEND_NODE_RSS_WARN_MB MB"
  echo "Frontend Node RSS hard limit   : $FRONTEND_NODE_RSS_HARD_LIMIT_MB MB"
  echo "Frontend Node RSS hard hits    : $FRONTEND_NODE_RSS_HARD_LIMIT_HITS"
  echo "Frontend Node RSS auto restart : $FRONTEND_NODE_RSS_AUTO_RESTART"
  echo "Frontend HMR disabled          : $FRONTEND_DISABLE_HMR"
  print_proxy_settings

  cleanup_app_processes
  cleanup_frontend_dev_processes
  cleanup_dev_binary
  prepare_tooling
  stage_proxy_runtimes
  resolve_frontend_dev_port
  resolve_wails_devserver
  ensure_embed_dist
  build_dev_binary
  start_watcher
  wait_for_frontend_dev_server

  echo "Starting Ant Browser (dev mode in project root)..."
  echo "Binary          : $DEV_BINARY"
  echo "Frontend URL    : http://127.0.0.1:$FRONTEND_PORT"
  echo "Wails dev server: http://$WAILS_DEVSERVER_ADDRESS"
  echo "App root & data : $ROOT_DIR (config.yaml / data/ / chrome/)"
  echo

  launch_dev_binary "" "http://127.0.0.1:$FRONTEND_PORT"
}

main() {
  parse_args "$@"

  if [[ "$SHOW_USAGE" -eq 1 ]]; then
    print_usage
    exit 0
  fi

  ensure_macos
  trap cleanup_on_exit EXIT
  trap handle_signal INT TERM

  case "$DEV_MODE" in
    stable)
      run_stable
      ;;
    live)
      run_live 0
      ;;
    limited)
      run_live 1
      ;;
    *)
      echo "[ERROR] Unsupported dev mode: $DEV_MODE" >&2
      echo >&2
      print_usage >&2
      exit 1
      ;;
  esac
}

main "$@"
