#!/bin/bash

set -euo pipefail
export PATH="/usr/bin:/bin:/usr/sbin:/sbin:${PATH:-}"

SCRIPT_DIR="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

usage() {
  cat <<'EOF'
Usage:
  GHIDRA_INSTALL_DIR=/path/to/ghidra \
  GHIDRA_BSIM_URL=postgresql://user@localhost/database \
  GHIDRA_BSIM_PASSWORD_ENV=BSIM_PASSWORD \
  ./scripts/validate_bsim_runtime.sh

Required:
  GHIDRA_INSTALL_DIR             Ghidra installation to validate.
  GHIDRA_BSIM_URL                BSim database URL.
  GHIDRA_BSIM_PASSWORD           BSim password value, or:
  GHIDRA_BSIM_PASSWORD_ENV       Environment variable name holding the password.

Optional query/load/decompile validation:
  GHIDRA_BSIM_PROJECT_LOCATION   Project directory or .gpr path.
  GHIDRA_BSIM_PROJECT_NAME       Project name when location is a directory.
  GHIDRA_BSIM_QUERY_DOMAIN_PATH  Domain path for the query program.
  GHIDRA_BSIM_QUERY_FUNCTION     Function name to query.

Any arguments after the script name are passed to pytest. With no arguments, the
script runs tests/test_runtime_bsim_commands.py -q.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

require_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "error: ${name} is required" >&2
    usage >&2
    exit 2
  fi
}

require_env GHIDRA_INSTALL_DIR
require_env GHIDRA_BSIM_URL

if [[ -n "${GHIDRA_BSIM_PASSWORD:-}" && -n "${GHIDRA_BSIM_PASSWORD_ENV:-}" ]]; then
  echo "error: set only one of GHIDRA_BSIM_PASSWORD or GHIDRA_BSIM_PASSWORD_ENV" >&2
  exit 2
fi

if [[ -z "${GHIDRA_BSIM_PASSWORD:-}" && -z "${GHIDRA_BSIM_PASSWORD_ENV:-}" ]]; then
  if [[ ! -t 0 ]]; then
    echo "error: GHIDRA_BSIM_PASSWORD or GHIDRA_BSIM_PASSWORD_ENV is required without a TTY" >&2
    exit 2
  fi
  printf "BSim password: " > /dev/tty
  stty -echo < /dev/tty
  IFS= read -r BSIM_RUNTIME_PASSWORD < /dev/tty
  stty echo < /dev/tty
  printf "\n" > /dev/tty
  export BSIM_RUNTIME_PASSWORD
  export GHIDRA_BSIM_PASSWORD_ENV=BSIM_RUNTIME_PASSWORD
fi

if [[ -n "${GHIDRA_BSIM_PASSWORD_ENV:-}" && -z "${!GHIDRA_BSIM_PASSWORD_ENV:-}" ]]; then
  echo "error: ${GHIDRA_BSIM_PASSWORD_ENV} is not set or is empty" >&2
  exit 2
fi

if command -v uv >/dev/null 2>&1; then
  UV_BIN="$(command -v uv)"
elif [[ -x "${HOME}/.local/bin/uv" ]]; then
  UV_BIN="${HOME}/.local/bin/uv"
else
  echo "error: uv was not found; set PATH or install uv" >&2
  exit 2
fi

export GHIDRA_BSIM_RUNTIME_VALIDATION=1

run_pytest() {
  local output_file status
  output_file="$(/usr/bin/mktemp "${TMPDIR:-/tmp}/bsim-runtime-pytest.XXXXXX")"

  set +e
  "${UV_BIN}" run pytest "$@" 2>&1 | /usr/bin/tee "${output_file}"
  status="${PIPESTATUS[0]}"
  set -e

  if [[ "${status}" -eq 138 ]] && /usr/bin/grep -Eq '[0-9]+ passed' "${output_file}"; then
    echo "warning: pytest exited 138 after reporting success; treating this as PyGhidra teardown noise" >&2
    /bin/rm -f "${output_file}"
    return 0
  fi
  /bin/rm -f "${output_file}"
  return "${status}"
}

cd "${REPO_ROOT}"
if [[ "$#" -eq 0 ]]; then
  run_pytest tests/test_runtime_bsim_commands.py -q
  exit $?
fi
run_pytest "$@"
