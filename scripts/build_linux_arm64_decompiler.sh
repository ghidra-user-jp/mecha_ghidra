#!/bin/bash

set -euo pipefail
export PATH="/usr/bin:/bin:/usr/sbin:/sbin:${PATH:-}"

SCRIPT_DIR="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# shellcheck disable=SC1091
source "${SCRIPT_DIR}/ghidra_release.env"

DEFAULT_OUTPUT_DIR="${REPO_ROOT}/dist"
DEFAULT_UPSTREAM_REF="${MECHA_GHIDRA_GHIDRA_RELEASE_TAG}"
DOCKER_IMAGE="${DOCKER_IMAGE:-ubuntu:24.04}"
OUTPUT_DIR="${DEFAULT_OUTPUT_DIR}"
WORK_DIR=""
UPSTREAM_REF="${GHIDRA_UPSTREAM_REF:-${DEFAULT_UPSTREAM_REF}}"
GHIDRA_DIST_URL="${GHIDRA_DIST_URL:-${MECHA_GHIDRA_GHIDRA_DIST_URL}}"
GHIDRA_DIST_SHA256="${GHIDRA_DIST_SHA256:-${MECHA_GHIDRA_GHIDRA_DIST_SHA256}}"
BUILD_PATCHED_DIST=1
KEEP_WORK_DIR=0
USE_DOCKER="auto"

usage() {
  cat <<'EOF'
Usage:
  ./scripts/build_linux_arm64_decompiler.sh [options]

Options:
  --output-dir DIR         Output directory. Default: ./dist
  --work-dir DIR           Working directory to reuse.
  --upstream-ref REF       Upstream Ghidra git ref/tag. Default: release tag from scripts/ghidra_release.env
  --ghidra-dist-url URL    Official Ghidra ZIP URL used for the patched ARM64 distribution.
  --ghidra-dist-sha256 HASH
                           SHA256 for the official Ghidra ZIP.
  --no-patched-dist        Build only the overlay tarball.
  --docker                 Force running the build inside a linux/arm64 Docker container.
  --no-docker              Run directly on the current host (requires Linux ARM64).
  --keep-work-dir          Keep the working directory after completion.
  -h, --help               Show this help.

Artifacts:
  - ghidra_*_linux_arm_64_decompiler_overlay.tar.gz
  - ghidra_*_linux_arm_64_decompiler.zip
  - matching .sha256 files
EOF
}

log_step() {
  echo
  echo "==> $1"
}

run_with_retry() {
  local attempts delay status
  attempts="$1"
  delay="$2"
  shift 2
  status=0
  for ((attempt=1; attempt<=attempts; attempt++)); do
    if "$@"; then
      return 0
    fi
    status=$?
    if [[ "${attempt}" -ge "${attempts}" ]]; then
      return "${status}"
    fi
    echo "Warning: command failed (attempt ${attempt}/${attempts}): $*" >&2
    echo "Retrying in ${delay}s..." >&2
    /bin/sleep "${delay}"
  done
  return "${status}"
}

is_linux_arm64() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"
  [[ "${os}" == "Linux" ]] && [[ "${arch}" == "aarch64" || "${arch}" == "arm64" ]]
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Error: required command not found: $1" >&2
    exit 127
  }
}

cleanup() {
  if [[ "${KEEP_WORK_DIR}" == "1" ]]; then
    return 0
  fi
  if [[ -n "${WORK_DIR}" && -d "${WORK_DIR}" ]]; then
    /bin/rm -rf "${WORK_DIR}"
  fi
}

trap cleanup EXIT

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir)
      [[ $# -ge 2 ]] || { echo "Error: --output-dir requires a value." >&2; exit 2; }
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --work-dir)
      [[ $# -ge 2 ]] || { echo "Error: --work-dir requires a value." >&2; exit 2; }
      WORK_DIR="$2"
      KEEP_WORK_DIR=1
      shift 2
      ;;
    --upstream-ref)
      [[ $# -ge 2 ]] || { echo "Error: --upstream-ref requires a value." >&2; exit 2; }
      UPSTREAM_REF="$2"
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
    --no-patched-dist)
      BUILD_PATCHED_DIST=0
      shift
      ;;
    --docker)
      USE_DOCKER="1"
      shift
      ;;
    --no-docker)
      USE_DOCKER="0"
      shift
      ;;
    --keep-work-dir)
      KEEP_WORK_DIR=1
      shift
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

if [[ "${USE_DOCKER}" == "auto" ]]; then
  if is_linux_arm64; then
    USE_DOCKER="0"
  else
    USE_DOCKER="1"
  fi
fi

/bin/mkdir -p "${OUTPUT_DIR}"
OUTPUT_DIR="$(cd "${OUTPUT_DIR}" && pwd)"

if [[ "${USE_DOCKER}" == "1" ]]; then
  require_command docker
  docker_inner_args=(--no-docker --output-dir /out --upstream-ref "${UPSTREAM_REF}" --ghidra-dist-url "${GHIDRA_DIST_URL}" --ghidra-dist-sha256 "${GHIDRA_DIST_SHA256}")
  docker_run_args=(--rm --platform linux/arm64
    -e DEBIAN_FRONTEND=noninteractive
    -v "${REPO_ROOT}:/workspace:ro"
    -v "${OUTPUT_DIR}:/out")
  if [[ -n "${WORK_DIR}" || "${KEEP_WORK_DIR}" == "1" ]]; then
    if [[ -z "${WORK_DIR}" ]]; then
      WORK_DIR="$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/mecha-ghidra-linux-arm64-host.XXXXXX")"
    fi
    /bin/mkdir -p "${WORK_DIR}"
    docker_run_args+=(-v "${WORK_DIR}:/work")
    docker_inner_args+=(--work-dir /work --keep-work-dir)
  fi
  if [[ "${BUILD_PATCHED_DIST}" == "0" ]]; then
    docker_inner_args+=(--no-patched-dist)
  fi
  log_step "Running linux_arm_64 decompiler build in Docker (${DOCKER_IMAGE})"
  docker run "${docker_run_args[@]}" \
    "${DOCKER_IMAGE}" \
    bash -lc 'set -euo pipefail
      export PATH="/usr/bin:/bin:/usr/sbin:/sbin:${PATH:-}"
      apt-get update
      apt-get install -y --no-install-recommends ca-certificates curl git unzip zip tar build-essential bison flex file openjdk-21-jdk-headless python3
      exec bash /workspace/scripts/build_linux_arm64_decompiler.sh "$@"' \
    bash "${docker_inner_args[@]}"
  exit 0
fi

if ! is_linux_arm64; then
  echo "Error: --no-docker mode requires a Linux ARM64 host." >&2
  exit 1
fi

require_command git
require_command curl
require_command unzip
require_command zip
require_command tar
require_command sha256sum
require_command java
require_command javac
require_command python3
require_command bison
require_command flex
require_command file

if [[ -z "${WORK_DIR}" ]]; then
  WORK_DIR="$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/mecha-ghidra-linux-arm64.XXXXXX")"
fi

GHIDRA_SRC_DIR="${WORK_DIR}/ghidra"
GHIDRA_DIST_ZIP="${WORK_DIR}/${MECHA_GHIDRA_GHIDRA_DIST_FILENAME}"
PATCH_ROOT="${WORK_DIR}/patch-root"
OVERLAY_ROOT="${WORK_DIR}/overlay-root"
OVERLAY_DIR="${OVERLAY_ROOT}/Ghidra/Features/Decompiler/os/linux_arm_64"
OVERLAY_TARBALL="${OUTPUT_DIR}/${MECHA_GHIDRA_ARM64_OVERLAY_BASENAME}"
PATCHED_DIST_ZIP="${OUTPUT_DIR}/${MECHA_GHIDRA_ARM64_PATCHED_DIST_BASENAME}"
FETCH_DEPS_DIR="${WORK_DIR}/fetch-deps-dummy"
DECOMPILER_DIR="${GHIDRA_SRC_DIR}/Ghidra/Features/Decompiler"
DECOMPILER_SETTINGS="${DECOMPILER_DIR}/settings.gradle"
DECOMPILER_BUILD="${DECOMPILER_DIR}/build.gradle"
DECOMPILER_BUILD_BACKUP="${DECOMPILER_DIR}/build.gradle.dev"

restore_decompiler_standalone_files() {
  if [[ -f "${DECOMPILER_BUILD_BACKUP}" ]]; then
    /bin/mv -f "${DECOMPILER_BUILD_BACKUP}" "${DECOMPILER_BUILD}"
  fi
  /bin/rm -f "${DECOMPILER_SETTINGS}"
}

log_step "Cloning upstream Ghidra (${UPSTREAM_REF})"
if [[ -d "${GHIDRA_SRC_DIR}/.git" ]]; then
  /usr/bin/git -C "${GHIDRA_SRC_DIR}" fetch --depth 1 origin "${UPSTREAM_REF}" || {
    echo "Error: failed during upstream clone refresh." >&2
    exit 1
  }
  /usr/bin/git -C "${GHIDRA_SRC_DIR}" checkout -f FETCH_HEAD || {
    echo "Error: failed during upstream checkout." >&2
    exit 1
  }
else
  if [[ -e "${GHIDRA_SRC_DIR}" ]]; then
    echo "Error: working tree path already exists and is not a git repository: ${GHIDRA_SRC_DIR}" >&2
    exit 1
  fi
  /usr/bin/git clone --depth 1 --branch "${UPSTREAM_REF}" https://github.com/NationalSecurityAgency/ghidra.git "${GHIDRA_SRC_DIR}" || {
    echo "Error: failed during upstream clone." >&2
    exit 1
  }
fi

log_step "Preparing upstream Gradle dependencies"
/bin/mkdir -p "${FETCH_DEPS_DIR}"
/usr/bin/printf "rootProject.name = 'mecha-ghidra-fetch-deps'\n" > "${FETCH_DEPS_DIR}/settings.gradle"
/usr/bin/printf "plugins { id 'base' }\n" > "${FETCH_DEPS_DIR}/build.gradle"
pushd "${FETCH_DEPS_DIR}" >/dev/null
run_with_retry 3 10 \
  "${GHIDRA_SRC_DIR}/gradlew" \
  --no-daemon \
  --console plain \
  -DhideDownloadProgress=true \
  -I "${GHIDRA_SRC_DIR}/gradle/support/fetchDependencies.gradle" \
  help || {
  echo "Error: failed during fetchDependencies." >&2
  exit 1
}
popd >/dev/null

log_step "Building linux_arm_64 native decompiler binaries"
restore_decompiler_standalone_files
trap 'restore_decompiler_standalone_files; cleanup' EXIT
pushd "${DECOMPILER_DIR}" >/dev/null
/usr/bin/printf "rootProject.name = 'DecompilerNative'\n" > "${DECOMPILER_SETTINGS}"
/bin/mv "${DECOMPILER_BUILD}" "${DECOMPILER_BUILD_BACKUP}"
/bin/cp buildNatives.gradle "${DECOMPILER_BUILD}"
run_with_retry 2 10 ../../../gradlew --no-daemon --console plain buildNatives_linux_arm_64 || {
  echo "Error: failed during native build." >&2
  exit 1
}
restore_decompiler_standalone_files
popd >/dev/null

BUILD_OUTPUT_DIR="${GHIDRA_SRC_DIR}/Ghidra/Features/Decompiler/build/os/linux_arm_64"
DECOMPILE_BIN="${BUILD_OUTPUT_DIR}/decompile"
SLEIGH_BIN="${BUILD_OUTPUT_DIR}/sleigh"

/bin/rm -rf "${OVERLAY_ROOT}" "${PATCH_ROOT}"

for binary in "${DECOMPILE_BIN}" "${SLEIGH_BIN}"; do
  [[ -x "${binary}" ]] || {
    echo "Error: expected ARM64 native binary was not produced: ${binary}" >&2
    exit 1
  }
  status=0
  "${binary}" >/dev/null 2>&1 || status=$?
  if [[ "${status}" == "126" || "${status}" == "127" ]]; then
    echo "Error: built binary is not executable on Linux ARM64: ${binary}" >&2
    exit 1
  fi
done

/bin/mkdir -p "${OVERLAY_DIR}"
/bin/cp "${DECOMPILE_BIN}" "${SLEIGH_BIN}" "${OVERLAY_DIR}/"

log_step "Packaging linux_arm_64 overlay"
tar -C "${OVERLAY_ROOT}" -czf "${OVERLAY_TARBALL}" Ghidra
sha256sum "${OVERLAY_TARBALL}" > "${OVERLAY_TARBALL}.sha256"

echo "Created overlay artifact: ${OVERLAY_TARBALL}"
file "${DECOMPILE_BIN}"
file "${SLEIGH_BIN}"

if [[ "${BUILD_PATCHED_DIST}" == "1" ]]; then
  log_step "Downloading official Ghidra distribution"
  curl -L "${GHIDRA_DIST_URL}" -o "${GHIDRA_DIST_ZIP}" || {
    echo "Error: failed during official Ghidra ZIP download." >&2
    exit 1
  }
  echo "${GHIDRA_DIST_SHA256}  ${GHIDRA_DIST_ZIP}" | sha256sum -c - || {
    echo "Error: downloaded official Ghidra ZIP failed SHA256 validation." >&2
    exit 1
  }

  /bin/mkdir -p "${PATCH_ROOT}"
  unzip -q "${GHIDRA_DIST_ZIP}" -d "${PATCH_ROOT}" || {
    echo "Error: failed while unpacking the official Ghidra ZIP." >&2
    exit 1
  }

  RELEASE_DIR="$(find "${PATCH_ROOT}" -mindepth 1 -maxdepth 1 -type d -name 'ghidra_*' | /usr/bin/head -n 1)"
  [[ -n "${RELEASE_DIR}" ]] || {
    echo "Error: failed to locate unpacked Ghidra release directory." >&2
    exit 1
  }

  /bin/mkdir -p "${RELEASE_DIR}/Ghidra/Features/Decompiler/os/linux_arm_64"
  /bin/cp "${DECOMPILE_BIN}" "${SLEIGH_BIN}" "${RELEASE_DIR}/Ghidra/Features/Decompiler/os/linux_arm_64/"

  log_step "Packaging patched ARM64 Ghidra distribution"
  pushd "${PATCH_ROOT}" >/dev/null
  zip -qr "${PATCHED_DIST_ZIP}" "$(/usr/bin/basename "${RELEASE_DIR}")" || {
    echo "Error: failed while creating the patched ARM64 Ghidra ZIP." >&2
    exit 1
  }
  popd >/dev/null
  sha256sum "${PATCHED_DIST_ZIP}" > "${PATCHED_DIST_ZIP}.sha256"
  echo "Created patched distribution: ${PATCHED_DIST_ZIP}"
fi
