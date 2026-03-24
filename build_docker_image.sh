#!/bin/bash

set -euo pipefail
export PATH="/usr/bin:/bin:/usr/sbin:/sbin:${PATH:-}"

SCRIPT_DIR="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${SCRIPT_DIR}"
DEFAULT_IMAGE_TAG="ghidra-mcp:local"
DEFAULT_PLATFORM="${DOCKER_PLATFORM:-linux/amd64}"
DEFAULT_GHIDRA_DIST_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.0.4_build/ghidra_12.0.4_PUBLIC_20260303.zip"
DEFAULT_GHIDRA_DIST_SHA256="c3b458661d69e26e203d739c0c82d143cc8a4a29d9e571f099c2cf4bda62a120"
DOCKER_CONTEXT=""
IMAGE_TAG="${DEFAULT_IMAGE_TAG}"
PLATFORM="${DEFAULT_PLATFORM}"
GHIDRA_DIST_URL="${GHIDRA_DIST_URL:-}"
GHIDRA_DIST_SHA256="${GHIDRA_DIST_SHA256:-}"
TEMP_DOCKER_CONFIG=""

cleanup() {
  if [[ -n "${TEMP_DOCKER_CONFIG}" && -d "${TEMP_DOCKER_CONFIG}" ]]; then
    /bin/rm -rf "${TEMP_DOCKER_CONFIG}"
  fi
}

trap cleanup EXIT

usage() {
  cat <<'EOF'
Usage:
  ./build_docker_image.sh [options]

Options:
  --tag NAME            Docker image tag to build. Default: ghidra-mcp:local
  --platform VALUE      Docker build platform. Default: linux/amd64
  --context NAME        Docker context to use for the build.
  --ghidra-dist-url URL Override the Ghidra distribution ZIP URL.
  --ghidra-dist-sha256 HASH
                        Override the expected SHA256 for the Ghidra ZIP.
  -h, --help            Show this help.

Environment:
  DOCKER_PLATFORM       Default platform override.
  GHIDRA_DIST_URL       Default Ghidra ZIP URL override.
  GHIDRA_DIST_SHA256    Default Ghidra ZIP SHA256 override.
EOF
}

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "${value}"
}

load_env_file() {
  local env_path="${REPO_ROOT}/.env"
  local line key value

  [[ -f "${env_path}" ]] || return 0

  while IFS= read -r line || [[ -n "${line}" ]]; do
    line="$(trim "${line}")"
    [[ -z "${line}" ]] && continue
    [[ "${line}" == \#* ]] && continue
    [[ "${line}" != *=* ]] && continue

    key="${line%%=*}"
    value="${line#*=}"
    key="$(trim "${key}")"
    value="$(trim "${value}")"

    case "${key}" in
      GHIDRA_DIST_URL)
        [[ -n "${GHIDRA_DIST_URL}" ]] || GHIDRA_DIST_URL="${value}"
        ;;
      GHIDRA_DIST_SHA256)
        [[ -n "${GHIDRA_DIST_SHA256}" ]] || GHIDRA_DIST_SHA256="${value}"
        ;;
    esac
  done < "${env_path}"
}

resolve_docker_host() {
  local context_name="$1"
  if [[ -n "${DOCKER_HOST:-}" ]]; then
    printf '%s' "${DOCKER_HOST}"
    return 0
  fi
  docker context inspect "${context_name}" --format '{{ (index .Endpoints "docker").Host }}'
}

prepare_docker_environment() {
  local docker_config_path="${DOCKER_CONFIG:-${HOME}/.docker}"
  local docker_config_json="${docker_config_path}/config.json"
  local credential_helper=""
  local docker_host=""

  if [[ ! -f "${docker_config_json}" ]]; then
    return 0
  fi

  credential_helper="$(/usr/bin/sed -n 's/.*"credsStore"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "${docker_config_json}" | /usr/bin/head -n 1)"
  [[ -n "${credential_helper}" ]] || return 0

  if command -v "docker-credential-${credential_helper}" >/dev/null 2>&1; then
    return 0
  fi

  docker_host="$(resolve_docker_host "${DOCKER_CONTEXT:-$(docker context show)}")"
  [[ -n "${docker_host}" ]] || {
    echo "Error: failed to resolve Docker host for context fallback." >&2
    exit 1
  }

  TEMP_DOCKER_CONFIG="$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/ghidra-mcp-docker-config.XXXXXX")"
  /usr/bin/printf '{"auths":{}}\n' > "${TEMP_DOCKER_CONFIG}/config.json"
  export DOCKER_CONFIG="${TEMP_DOCKER_CONFIG}"
  export DOCKER_HOST="${docker_host}"

  echo "Warning: docker-credential-${credential_helper} was not found; using temporary Docker config fallback." >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag)
      [[ $# -ge 2 ]] || { echo "Error: --tag requires a value." >&2; exit 2; }
      IMAGE_TAG="$2"
      shift 2
      ;;
    --platform)
      [[ $# -ge 2 ]] || { echo "Error: --platform requires a value." >&2; exit 2; }
      PLATFORM="$2"
      shift 2
      ;;
    --context)
      [[ $# -ge 2 ]] || { echo "Error: --context requires a value." >&2; exit 2; }
      DOCKER_CONTEXT="$2"
      shift 2
      ;;
    --ghidra-dist-url)
      [[ $# -ge 2 ]] || { echo "Error: --ghidra-dist-url requires a value." >&2; exit 2; }
      GHIDRA_DIST_URL="$2"
      shift 2
      ;;
    --ghidra-dist-sha256)
      [[ $# -ge 2 ]] || { echo "Error: --ghidra-dist-sha256 requires a value." >&2; exit 2; }
      GHIDRA_DIST_SHA256="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Error: unknown option: $1" >&2
      echo >&2
      usage >&2
      exit 2
      ;;
  esac
done

load_env_file

GHIDRA_DIST_URL="${GHIDRA_DIST_URL:-${DEFAULT_GHIDRA_DIST_URL}}"
GHIDRA_DIST_SHA256="${GHIDRA_DIST_SHA256:-${DEFAULT_GHIDRA_DIST_SHA256}}"

if ! command -v docker >/dev/null 2>&1; then
  echo "Error: docker command not found." >&2
  exit 127
fi

if ! docker buildx version >/dev/null 2>&1; then
  echo "Error: docker buildx is required to build a linux/amd64 image reliably." >&2
  exit 127
fi

DOCKER_CMD=(docker)
if [[ -n "${DOCKER_CONTEXT}" && -z "${DOCKER_HOST:-}" ]]; then
  DOCKER_CMD+=(--context "${DOCKER_CONTEXT}")
fi

if ! "${DOCKER_CMD[@]}" info >/dev/null 2>&1; then
  prepare_docker_environment
fi

DOCKER_CMD=(docker)
if [[ -n "${DOCKER_CONTEXT}" && -z "${DOCKER_HOST:-}" ]]; then
  DOCKER_CMD+=(--context "${DOCKER_CONTEXT}")
fi

echo "Building Docker image ${IMAGE_TAG}"
if [[ -n "${DOCKER_CONTEXT}" ]]; then
  echo "Using docker context: ${DOCKER_CONTEXT}"
fi
echo "Using docker platform: ${PLATFORM}"
echo "Repository root: ${REPO_ROOT}"

"${DOCKER_CMD[@]}" buildx build \
  --load \
  --platform "${PLATFORM}" \
  -f "${REPO_ROOT}/Dockerfile" \
  --build-arg "TARGETPLATFORM=${PLATFORM}" \
  --build-arg "GHIDRA_DIST_URL=${GHIDRA_DIST_URL}" \
  --build-arg "GHIDRA_DIST_SHA256=${GHIDRA_DIST_SHA256}" \
  -t "${IMAGE_TAG}" \
  "${REPO_ROOT}"

echo
echo "Build completed: ${IMAGE_TAG}"
if [[ -n "${DOCKER_CONTEXT}" ]]; then
  "${DOCKER_CMD[@]}" image ls "${IMAGE_TAG}"
else
  docker image ls "${IMAGE_TAG}"
fi
