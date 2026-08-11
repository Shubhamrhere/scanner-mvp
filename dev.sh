#!/usr/bin/env bash
#
# Developer workflow for Scanner MVP.
#
# Runs the Flask app and the Celery worker directly on the host with
# hot-reload, while Postgres, Redis and OpenVAS run in Docker containers.
#
# Usage:
#   ./dev.sh setup            # first time: create venv + install deps
#   ./dev.sh up               # start infra containers (db, redis, openvas)
#   ./dev.sh dev              # infra + worker (background) + Flask (foreground)
#   ./dev.sh web              # run Flask with auto-reload (own terminal)
#   ./dev.sh worker           # run Celery worker with auto-reload (own terminal)
#   ./dev.sh logs             # follow infra + worker logs
#   ./dev.sh test             # smoke test against the local stack
#   ./dev.sh status           # show running infra containers
#   ./dev.sh stop             # stop infra containers (keep data)
#   ./dev.sh down             # stop and remove infra containers (keep data)
#   ./dev.sh clean            # stop, remove containers + volumes, delete venv
#   ./dev.sh help             # show this help
#
# Suggested workflow:
#   ./dev.sh setup && ./dev.sh dev
#   (in another terminal) ./dev.sh logs

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${ROOT_DIR}/venv"
LOG_DIR="${ROOT_DIR}/logs"
WORKER_LOG="${LOG_DIR}/worker.log"
PID_FILE="${LOG_DIR}/worker.pid"

# Infra connection settings (override via env if needed)
DB_USER="${DB_USER:-scanner}"
DB_PASSWORD="${DB_PASSWORD:-scanner}"
DB_NAME="${DB_NAME:-scanner}"
DB_PORT="${DB_PORT:-5432}"
REDIS_PORT="${REDIS_PORT:-6379}"
GMP_HOST="${GMP_HOST:-localhost}"

COMPOSE="docker compose -f ${ROOT_DIR}/docker-compose.yml -f ${ROOT_DIR}/docker-compose.dev.yml"

export ROOT_DIR
export DATABASE_URL="postgresql://${DB_USER}:${DB_PASSWORD}@localhost:${DB_PORT}/${DB_NAME}"
export CELERY_BROKER_URL="redis://localhost:${REDIS_PORT}/0"
export CELERY_RESULT_BACKEND="redis://localhost:${REDIS_PORT}/0"
export FLASK_APP="app.py"
export FLASK_ENV="development"
export FLASK_DEBUG="1"
export PYTHONPATH="${ROOT_DIR}"
export SECRET_KEY="${SECRET_KEY:-dev-secret-key-12345}"
export GVM_HOST="${GMP_HOST}"

C_GREEN='\033[0;32m'
C_YELLOW='\033[1;33m'
C_RED='\033[0;31m'
C_CYAN='\033[0;36m'
C_RESET='\033[0m'

info()  { printf "${C_CYAN}[dev]${C_RESET} %s\n" "$*"; }
ok()    { printf "${C_GREEN}[ok]${C_RESET} %s\n" "$*"; }
warn()  { printf "${C_YELLOW}[warn]${C_RESET} %s\n" "$*"; }
fail()  { printf "${C_RED}[error]${C_RESET} %s\n" "$*" >&2; exit 1; }

venv_python() {
    if [[ -x "${VENV_DIR}/Scripts/python.exe" ]]; then
        printf '%s' "${VENV_DIR}/Scripts/python.exe"
    elif [[ -x "${VENV_DIR}/bin/python" ]]; then
        printf '%s' "${VENV_DIR}/bin/python"
    else
        printf '%s' ""
    fi
}

IS_WINDOWS=0
case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) IS_WINDOWS=1 ;;
esac

# Celery's default prefork pool is not supported on Windows.
CELERY_POOL=""
if [[ "${IS_WINDOWS}" == "1" ]]; then
    CELERY_POOL="--pool=solo"
fi

require_venv() {
    if [[ -z "$(venv_python)" ]]; then
        fail "venv not found. Run './dev.sh setup' first."
    fi
}

wait_for_db() {
    local py; py="$(venv_python)"
    info "Waiting for Postgres to be ready ..."
    "${py:-python}" - <<'PY'
import os
import sys
import time

import psycopg2

url = os.environ["DATABASE_URL"]
for _ in range(30):
    try:
        psycopg2.connect(url).close()
        print("Postgres is ready")
        sys.exit(0)
    except Exception:
        time.sleep(1)
print("Postgres did not become ready in time")
sys.exit(1)
PY
}

ensure_infra() {
    local running
    running="$(${COMPOSE} ps --services --status running 2>/dev/null || true)"
    if [[ "${running}" != *"db"* ]]; then
        warn "Infra containers are not running. Starting them ..."
        cmd_up
    fi
}

stop_worker() {
    if [[ -f "${PID_FILE}" ]]; then
        local pid
        pid="$(cat "${PID_FILE}")"
        warn "Stopping background worker (pid ${pid})"
        kill "${pid}" 2>/dev/null || true
        rm -f "${PID_FILE}"
    fi
}

cmd_setup() {
    info "Creating virtualenv at ${VENV_DIR} ..."
    python -m venv "${VENV_DIR}"
    local py; py="$(venv_python)"
    "${py:-python}" -m pip install --upgrade pip
    "${py:-python}" -m pip install -r "${ROOT_DIR}/requirements.txt"
    if [[ -f "${ROOT_DIR}/requirements-dev.txt" ]]; then
        "${py:-python}" -m pip install -r "${ROOT_DIR}/requirements-dev.txt"
    fi
    ok "Setup complete. Run './dev.sh dev'"
}

cmd_up() {
    info "Starting infra (db, redis, openvas) ..."
    ${COMPOSE} up -d db redis openvas
    wait_for_db
    ok "Infra is up. Run './dev.sh dev' (or './dev.sh web' + './dev.sh worker')."
}

cmd_web() {
    require_venv
    local py; py="$(venv_python)"
    ensure_infra
    info "Starting Flask dev server on http://localhost:5000 (auto-reload on)"
    exec "${py}" -m flask run --debug
}

cmd_worker() {
    require_venv
    local py; py="$(venv_python)"
    ensure_infra
    info "Starting Celery worker (auto-reload on)"
    exec "${py}" -m celery -A tasks.celery worker --loglevel=info --autoreload ${CELERY_POOL}
}

cmd_dev() {
    require_venv
    local py; py="$(venv_python)"
    ensure_infra
    mkdir -p "${LOG_DIR}"
    info "Starting Celery worker in background (logs -> ${WORKER_LOG})"
    "${py}" -m celery -A tasks.celery worker --loglevel=info --autoreload ${CELERY_POOL} >"${WORKER_LOG}" 2>&1 &
    local worker_pid=$!
    echo "${worker_pid}" > "${PID_FILE}"
    trap 'warn "Stopping background worker"; kill "$(cat "${PID_FILE}")" 2>/dev/null || true; rm -f "${PID_FILE}";' EXIT
    info "Starting Flask dev server on http://localhost:5000 (Ctrl+C to stop everything)"
    "${py}" -m flask run --debug
}

cmd_logs() {
    local tail_pid=""
    if [[ -f "${PID_FILE}" ]]; then
        info "Tailing worker log (${WORKER_LOG})"
        tail -f "${WORKER_LOG}" &
        tail_pid=$!
    fi
    info "Following infra logs (Ctrl+C to stop)"
    ${COMPOSE} logs -f
    if [[ -n "${tail_pid}" ]]; then
        kill "${tail_pid}" 2>/dev/null || true
    fi
}

cmd_test() {
    require_venv
    local py; py="$(venv_python)"
    ensure_infra
    info "Running smoke test ..."
    "${py}" - <<'PY'
import os
import sys

import redis

sys.path.insert(0, os.environ["ROOT_DIR"])

from app import create_app
from models import Agent, Asset, Finding, Scan

print("DATABASE_URL      :", os.environ["DATABASE_URL"])
print("CELERY_BROKER_URL :", os.environ["CELERY_BROKER_URL"])

app = create_app()
with app.app_context():
    print("assets   :", Asset.query.count())
    print("scans    :", Scan.query.count())
    print("findings :", Finding.query.count())
    print("agents   :", [a.name for a in Agent.query.all()])

r = redis.Redis.from_url(os.environ["CELERY_BROKER_URL"])
r.ping()
print("redis ping : OK")

print("SMOKE TEST PASSED")
PY
    ok "Smoke test passed."
}

cmd_status() {
    ${COMPOSE} ps
}

cmd_stop() {
    stop_worker
    ${COMPOSE} stop
    ok "Stopped. Use './dev.sh up' to start again."
}

cmd_down() {
    stop_worker
    ${COMPOSE} down
    ok "Containers removed. Data volumes preserved."
}

cmd_clean() {
    stop_worker
    ${COMPOSE} down -v
    rm -rf "${VENV_DIR}" "${LOG_DIR}"
    ok "Cleaned containers, volumes, venv and logs."
}

cmd_help() {
    cat <<'EOF'
Developer workflow for Scanner MVP
-----------------------------------
The app and Celery worker run on the host with hot-reload while
Postgres, Redis and OpenVAS run in Docker.

Commands:
  setup    create venv + install requirements (+ dev deps)
  up       start infra containers (db, redis, openvas)
  dev      infra + background worker + Flask (foreground) with hot-reload
  web      run Flask only (auto-reload)
  worker   run Celery worker only (auto-reload)
  logs     follow infra and worker logs
  test     smoke test (app boots, DB reachable, Redis ping)
  status   show infra container state
  stop     stop infra containers (keep data)
  down     stop and remove infra containers (keep data volumes)
  clean    stop, remove containers + volumes, delete venv and logs
  help     show this help

Typical workflow:
  ./dev.sh setup && ./dev.sh dev
  # in another terminal:
  ./dev.sh logs

Notes:
  - Flask serves on http://localhost:5000 (debugger + auto-reload).
  - OpenVAS GMP connects to localhost:9390 in dev (GVM_HOST env).
  - Env overrides: DB_PORT, REDIS_PORT, DB_USER, DB_PASSWORD, DB_NAME, GMP_HOST
EOF
}

case "${1:-help}" in
    setup) cmd_setup ;;
    up) cmd_up ;;
    dev) cmd_dev ;;
    web) cmd_web ;;
    worker) cmd_worker ;;
    logs) cmd_logs ;;
    test) cmd_test ;;
    status|ps) cmd_status ;;
    stop) cmd_stop ;;
    down) cmd_down ;;
    clean) cmd_clean ;;
    help|--help|-h) cmd_help ;;
    *) fail "Unknown command: ${1}. Run './dev.sh help'" ;;
esac
