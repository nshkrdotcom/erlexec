#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-fast}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
JOBS="${JOBS:-4}"

usage() {
  cat <<'USAGE'
Usage:
  scripts/eunit_harness.sh [fast|full|stability]

Modes:
  fast:
    - Build C++ port in debug mode (OPTIMIZE=0)
    - Compile Erlang modules with -DTEST
    - Run EUnit once (default RUN_COUNT=900)

  full:
    - Build C++ port in release mode (OPTIMIZE=3), run EUnit once (RUN_COUNT=900)
    - Build C++ port in debug mode   (OPTIMIZE=0), run EUnit once (RUN_COUNT=900)

  stability:
    - Build C++ port in debug mode (OPTIMIZE=0)
    - Compile Erlang modules with -DTEST
    - Run EUnit N times (default STABILITY_RUNS=10, RUN_COUNT=900)
    - Exits non-zero if any run fails.

Environment overrides:
  RUN_COUNT=<int>         Concurrency count for exec_run_many_test_.
  PID_SLEEP_SEC=<int>     Optional value passed to tests (leave unset for test defaults).
  STABILITY_RUNS=<int>    Number of loop runs for stability mode.
  JOBS=<int>              Parallel jobs for C++ build (default 4).
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

build_native() {
  local optimize="$1"
  local clean_first="${2:-1}"
  echo "==> Building c_src (OPTIMIZE=$optimize)"
  if [[ "$clean_first" == "1" ]]; then
    (cd "$ROOT_DIR" && make -C c_src clean)
  fi
  (cd "$ROOT_DIR" && OPTIMIZE="$optimize" make -C c_src -j"$JOBS")
}

compile_erlang_tests() {
  echo "==> Compiling Erlang modules with -DTEST"
  mkdir -p "$ROOT_DIR/ebin"
  find "$ROOT_DIR/ebin" -type f -delete
  (cd "$ROOT_DIR" && erlc -DTEST -I include -o ebin src/*.erl test/*.erl)
}

run_eunit_once() {
  local run_count="$1"
  local pid_sleep_sec="${2:-}"
  local start end elapsed

  start="$(now_ms)"
  if [[ -n "$pid_sleep_sec" ]]; then
    (
      cd "$ROOT_DIR" &&
        RUN_COUNT="$run_count" \
        PID_SLEEP_SEC="$pid_sleep_sec" \
        erl -noshell -pa ebin \
        -eval 'Res=eunit:test([exec,security_exec_tests],[verbose]), halt(case Res of ok -> 0; _ -> 1 end).'
    )
  else
    (
      cd "$ROOT_DIR" &&
        RUN_COUNT="$run_count" \
        erl -noshell -pa ebin \
        -eval 'Res=eunit:test([exec,security_exec_tests],[verbose]), halt(case Res of ok -> 0; _ -> 1 end).'
    )
  fi
  end="$(now_ms)"
  elapsed=$((end - start))
  echo "EUNIT_ELAPSED_MS=$elapsed"
}

run_stability() {
  local runs="$1"
  local run_count="$2"
  local pid_sleep_sec="${3:-}"

  local pass=0 fail=0 total_ms=0 max_ms=0 min_ms=0 elapsed=0

  for ((i = 1; i <= runs; i++)); do
    echo "==> Stability run $i/$runs"
    local start end
    start="$(now_ms)"
    if [[ -n "$pid_sleep_sec" ]]; then
      if (
        cd "$ROOT_DIR" &&
          RUN_COUNT="$run_count" \
          PID_SLEEP_SEC="$pid_sleep_sec" \
          erl -noshell -pa ebin \
          -eval 'Res=eunit:test([exec,security_exec_tests],[verbose]), halt(case Res of ok -> 0; _ -> 1 end).'
      ); then
        pass=$((pass + 1))
      else
        fail=$((fail + 1))
      fi
    elif (
      cd "$ROOT_DIR" &&
        RUN_COUNT="$run_count" \
        erl -noshell -pa ebin \
        -eval 'Res=eunit:test([exec,security_exec_tests],[verbose]), halt(case Res of ok -> 0; _ -> 1 end).'
    ); then
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
  require_cmd make
  require_cmd erl
  require_cmd erlc

  local run_count="${RUN_COUNT:-}"

  case "$MODE" in
    fast)
      build_native 0
      compile_erlang_tests
      run_eunit_once "${run_count:-900}" "${PID_SLEEP_SEC:-}"
      ;;
    full)
      build_native 3
      compile_erlang_tests
      run_eunit_once "${run_count:-900}" "${PID_SLEEP_SEC:-}"

      build_native 0
      compile_erlang_tests
      run_eunit_once "${run_count:-900}" "${PID_SLEEP_SEC:-}"
      ;;
    stability)
      local stability_runs="${STABILITY_RUNS:-10}"
      build_native 0
      compile_erlang_tests
      run_stability "$stability_runs" "${run_count:-900}" "${PID_SLEEP_SEC:-}"
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
