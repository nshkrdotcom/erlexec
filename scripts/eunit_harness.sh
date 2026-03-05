#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-fast}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'USAGE'
Usage:
  scripts/eunit_harness.sh [fast|full|stability]

Modes:
  fast:
    - Run canonical `rebar3 clean` followed by `rebar3 eunit` in debug mode (OPTIMIZE=0)
    - Uses the standard rebar build/test path, including native pre-hooks

  full:
    - Run canonical `rebar3 clean` + `rebar3 eunit` in release mode (OPTIMIZE=3)
    - Run canonical `rebar3 clean` + `rebar3 eunit` in debug mode   (OPTIMIZE=0)

  stability:
    - Run canonical `rebar3 clean` + `rebar3 eunit` in debug mode (OPTIMIZE=0)
    - Repeat N times (default STABILITY_RUNS=10, RUN_COUNT=900)
    - Exits non-zero if any run fails.

Environment overrides:
  RUN_COUNT=<int>         Concurrency count for exec_run_many_test_.
  PID_SLEEP_SEC=<int>     Optional value passed to tests (leave unset for test defaults).
  STABILITY_RUNS=<int>    Number of loop runs for stability mode.
  SANITIZE=<spec>         Optional sanitizer list passed to the native build.
  CXX=<compiler>          Override the native compiler used by rebar pre-hooks.
USAGE
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Missing required command: $cmd" >&2
    exit 127
  fi
}

now_ms() {
  date +%s%3N
}

otp_version() {
  erl -noshell -noinput \
    -eval 'io:format("~ts", [erlang:system_info(otp_release)]), halt(0).'
}

compiler_bin() {
  if [[ -n "${CXX:-}" ]]; then
    printf '%s\n' "$CXX"
  elif command -v g++ >/dev/null 2>&1; then
    printf '%s\n' "g++"
  else
    printf '%s\n' "c++"
  fi
}

print_runtime_info() {
  local compiler
  compiler="$(compiler_bin)"
  echo "HARNESS_MODE=$MODE"
  echo "OTP_VERSION=$(otp_version)"
  echo "REBAR3_VERSION=$(rebar3 version | head -n 1)"
  echo "CXX=$compiler"
  if command -v "$compiler" >/dev/null 2>&1; then
    "$compiler" --version | head -n 1
  fi
}

run_eunit_once() {
  local optimize="$1"
  local sanitize="${2:-}"
  local run_count="$3"
  local pid_sleep_sec="${4:-}"
  local start end elapsed
  local -a env_args

  env_args=(
    "OPTIMIZE=$optimize"
    "SANITIZE=$sanitize"
    "RUN_COUNT=$run_count"
  )
  if [[ -n "$pid_sleep_sec" ]]; then
    env_args+=("PID_SLEEP_SEC=$pid_sleep_sec")
  fi

  start="$(now_ms)"
  echo "==> Running rebar3 clean && rebar3 eunit (OPTIMIZE=$optimize SANITIZE=${sanitize:-none})"
  (
    cd "$ROOT_DIR" &&
      env "${env_args[@]}" make -C c_src info &&
      env "${env_args[@]}" rebar3 clean &&
      env "${env_args[@]}" rebar3 eunit
  )
  end="$(now_ms)"
  elapsed=$((end - start))
  echo "EUNIT_ELAPSED_MS=$elapsed"
}

run_stability() {
  local runs="$1"
  local optimize="$2"
  local sanitize="${3:-}"
  local run_count="$4"
  local pid_sleep_sec="${5:-}"

  local pass=0 fail=0 total_ms=0 max_ms=0 min_ms=0 elapsed=0

  for ((i = 1; i <= runs; i++)); do
    echo "==> Stability run $i/$runs"
    local start end
    start="$(now_ms)"
    if run_eunit_once "$optimize" "$sanitize" "$run_count" "$pid_sleep_sec"; then
      pass=$((pass + 1))
    else
      fail=$((fail + 1))
    fi
    end="$(now_ms)"
    elapsed=$((end - start))

    total_ms=$((total_ms + elapsed))
    if ((i == 1)); then
      min_ms="$elapsed"
      max_ms="$elapsed"
    else
      if ((elapsed < min_ms)); then min_ms="$elapsed"; fi
      if ((elapsed > max_ms)); then max_ms="$elapsed"; fi
    fi
    echo "RUN_${i}_MS=$elapsed"
  done

  local avg_ms=$((total_ms / runs))
  echo "STABILITY_SUMMARY runs=$runs pass=$pass fail=$fail avg_ms=$avg_ms min_ms=$min_ms max_ms=$max_ms"

  if ((fail > 0)); then
    echo "Stability mode failed: $fail/$runs runs failed." >&2
    return 1
  fi
}

main() {
  require_cmd rebar3
  require_cmd make
  require_cmd erl

  local run_count="${RUN_COUNT:-}"
  local sanitize="${SANITIZE:-}"
  print_runtime_info

  case "$MODE" in
    fast)
      run_eunit_once 0 "$sanitize" "${run_count:-900}" "${PID_SLEEP_SEC:-}"
      ;;
    full)
      run_eunit_once 3 "$sanitize" "${run_count:-900}" "${PID_SLEEP_SEC:-}"
      run_eunit_once 0 "$sanitize" "${run_count:-900}" "${PID_SLEEP_SEC:-}"
      ;;
    stability)
      local stability_runs="${STABILITY_RUNS:-10}"
      run_stability "$stability_runs" 0 "$sanitize" "${run_count:-900}" "${PID_SLEEP_SEC:-}"
      ;;
    -h|--help|help)
      usage
      ;;
    *)
      echo "Unknown mode: $MODE" >&2
      usage
      exit 2
      ;;
  esac
}

main "$@"
