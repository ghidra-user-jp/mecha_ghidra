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
TARGET_PLATFORM="linux_arm_64"

usage() {
  cat <<'EOF'
Usage:
  ./scripts/build_decompiler_natives.sh [options]

Options:
  --platform PLATFORM      Decompiler platform to build. Supported:
                           linux_arm_64, mac_arm_64, mac_x86_64.
                           Default: linux_arm_64
  --output-dir DIR         Output directory. Default: ./dist
  --work-dir DIR           Working directory to reuse.
  --upstream-ref REF       Upstream Ghidra git ref/tag. Default: release tag from scripts/ghidra_release.env
  --ghidra-dist-url URL    Official Ghidra ZIP URL used for the patched distribution.
  --ghidra-dist-sha256 HASH
                           SHA256 for the official Ghidra ZIP.
  --no-patched-dist        Build only the overlay tarball.
  --docker                 Force running linux_arm_64 build inside a linux/arm64 Docker container.
  --no-docker              Run directly on the current host.
  --keep-work-dir          Keep the working directory after completion.
  -h, --help               Show this help.

Artifacts:
  - ghidra_*_<platform>_decompiler_overlay.tar.gz
  - ghidra_*_<platform>_decompiler.zip
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

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Error: required command not found: $1" >&2
    exit 127
  }
}

platform_env_key() {
  case "$1" in
    linux_arm_64)
      echo "LINUX_ARM64"
      ;;
    mac_arm_64)
      echo "MAC_ARM64"
      ;;
    mac_x86_64)
      echo "MAC_X86_64"
      ;;
    *)
      echo "Error: unsupported decompiler platform: $1" >&2
      exit 2
      ;;
  esac
}

current_platform() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"
  case "${os}:${arch}" in
    Linux:aarch64|Linux:arm64)
      echo "linux_arm_64"
      ;;
    Linux:x86_64|Linux:amd64)
      echo "linux_x86_64"
      ;;
    Darwin:arm64|Darwin:aarch64)
      echo "mac_arm_64"
      ;;
    Darwin:x86_64|Darwin:amd64)
      echo "mac_x86_64"
      ;;
    *)
      echo "unknown"
      ;;
  esac
}

supports_docker_platform() {
  [[ "$1" == "linux_arm_64" ]]
}

artifact_basename() {
  local key suffix var_name value
  key="$(platform_env_key "${TARGET_PLATFORM}")"
  suffix="$1"
  var_name="MECHA_GHIDRA_${key}_${suffix}_BASENAME"
  value="${!var_name:-}"
  if [[ -n "${value}" ]]; then
    echo "${value}"
    return 0
  fi
  case "${suffix}" in
    OVERLAY)
      echo "${MECHA_GHIDRA_GHIDRA_RELEASE_NAME}_${TARGET_PLATFORM}_decompiler_overlay.tar.gz"
      ;;
    PATCHED_DIST)
      echo "${MECHA_GHIDRA_GHIDRA_RELEASE_NAME}_${TARGET_PLATFORM}_decompiler.zip"
      ;;
    *)
      echo "Error: unsupported artifact suffix: ${suffix}" >&2
      exit 2
      ;;
  esac
}

write_sha256_file() {
  local path
  path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${path}" > "${path}.sha256"
  else
    require_command shasum
    shasum -a 256 "${path}" > "${path}.sha256"
  fi
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
    --platform)
      [[ $# -ge 2 ]] || { echo "Error: --platform requires a value." >&2; exit 2; }
      TARGET_PLATFORM="$2"
      shift 2
      ;;
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

platform_env_key "${TARGET_PLATFORM}" >/dev/null

if [[ "${USE_DOCKER}" == "auto" ]]; then
  if [[ "$(current_platform)" == "${TARGET_PLATFORM}" ]]; then
    USE_DOCKER="0"
  elif supports_docker_platform "${TARGET_PLATFORM}"; then
    USE_DOCKER="1"
  else
    USE_DOCKER="0"
  fi
fi

/bin/mkdir -p "${OUTPUT_DIR}"
OUTPUT_DIR="$(cd "${OUTPUT_DIR}" && pwd)"

if [[ "${USE_DOCKER}" == "1" ]]; then
  if ! supports_docker_platform "${TARGET_PLATFORM}"; then
    echo "Error: Docker build mode is only supported for linux_arm_64." >&2
    exit 2
  fi
  require_command docker
  docker_inner_args=(--no-docker --platform "${TARGET_PLATFORM}" --output-dir /out --upstream-ref "${UPSTREAM_REF}" --ghidra-dist-url "${GHIDRA_DIST_URL}" --ghidra-dist-sha256 "${GHIDRA_DIST_SHA256}")
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
  log_step "Running ${TARGET_PLATFORM} decompiler build in Docker (${DOCKER_IMAGE})"
  docker run "${docker_run_args[@]}" \
    "${DOCKER_IMAGE}" \
    bash -lc 'set -euo pipefail
      export PATH="/usr/bin:/bin:/usr/sbin:/sbin:${PATH:-}"
      apt-get update
      apt-get install -y --no-install-recommends ca-certificates curl git unzip zip tar build-essential bison flex file openjdk-21-jdk-headless python3
      exec bash /workspace/scripts/build_decompiler_natives.sh "$@"' \
    bash "${docker_inner_args[@]}"
  exit 0
fi

if [[ "$(current_platform)" != "${TARGET_PLATFORM}" ]]; then
  echo "Error: --no-docker mode for ${TARGET_PLATFORM} requires a matching host. Current host is $(current_platform)." >&2
  exit 1
fi

require_command git
require_command curl
require_command unzip
require_command zip
require_command tar
require_command java
require_command javac
require_command python3
require_command file

if [[ "${TARGET_PLATFORM}" == linux_* ]]; then
  require_command bison
  require_command flex
fi

if [[ -z "${WORK_DIR}" ]]; then
  WORK_DIR="$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/mecha-ghidra-${TARGET_PLATFORM}.XXXXXX")"
fi

GHIDRA_SRC_DIR="${WORK_DIR}/ghidra"
GHIDRA_DIST_ZIP="${WORK_DIR}/${MECHA_GHIDRA_GHIDRA_DIST_FILENAME}"
PATCH_ROOT="${WORK_DIR}/patch-root"
OVERLAY_ROOT="${WORK_DIR}/overlay-root"
OVERLAY_DIR="${OVERLAY_ROOT}/Ghidra/Features/Decompiler/os/${TARGET_PLATFORM}"
OVERLAY_TARBALL="${OUTPUT_DIR}/$(artifact_basename OVERLAY)"
PATCHED_DIST_ZIP="${OUTPUT_DIR}/$(artifact_basename PATCHED_DIST)"
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

log_step "Building ${TARGET_PLATFORM} native decompiler binaries"
restore_decompiler_standalone_files
trap 'restore_decompiler_standalone_files; cleanup' EXIT
pushd "${DECOMPILER_DIR}" >/dev/null
/usr/bin/printf "rootProject.name = 'DecompilerNative'\n" > "${DECOMPILER_SETTINGS}"
/bin/mv "${DECOMPILER_BUILD}" "${DECOMPILER_BUILD_BACKUP}"
/bin/cp buildNatives.gradle "${DECOMPILER_BUILD}"
run_with_retry 2 10 ../../../gradlew --no-daemon --console plain "buildNatives_${TARGET_PLATFORM}" || {
  echo "Error: failed during native build." >&2
  exit 1
}
restore_decompiler_standalone_files
popd >/dev/null

BUILD_OUTPUT_DIR="${GHIDRA_SRC_DIR}/Ghidra/Features/Decompiler/build/os/${TARGET_PLATFORM}"
DECOMPILE_BIN="${BUILD_OUTPUT_DIR}/decompile"
SLEIGH_BIN="${BUILD_OUTPUT_DIR}/sleigh"

/bin/rm -rf "${OVERLAY_ROOT}" "${PATCH_ROOT}"

for binary in "${DECOMPILE_BIN}" "${SLEIGH_BIN}"; do
  [[ -x "${binary}" ]] || {
    echo "Error: expected native binary was not produced: ${binary}" >&2
    exit 1
  }
  status=0
  "${binary}" >/dev/null 2>&1 || status=$?
  if [[ "${status}" == "126" || "${status}" == "127" ]]; then
    echo "Error: built binary is not executable on this host: ${binary}" >&2
    exit 1
  fi
done

/bin/mkdir -p "${OVERLAY_DIR}"
/bin/cp "${DECOMPILE_BIN}" "${SLEIGH_BIN}" "${OVERLAY_DIR}/"

# Preserve the upstream notices and the Decompiler module's third-party zlib
# license in every standalone overlay.  The patched full distribution already
# carries these files, but the overlay is also published as an independent
# artifact and must remain self-describing when redistributed on its own.
for required_license_file in \
  LICENSE \
  NOTICE \
  DISCLAIMER.md \
  licenses/zlib_License.txt
do
  [[ -f "${GHIDRA_SRC_DIR}/${required_license_file}" ]] || {
    echo "Error: required upstream license file is missing: ${required_license_file}" >&2
    exit 1
  }
done
/bin/mkdir -p "${OVERLAY_ROOT}/licenses"
/bin/cp "${GHIDRA_SRC_DIR}/LICENSE" "${OVERLAY_ROOT}/LICENSE"
/bin/cp "${GHIDRA_SRC_DIR}/NOTICE" "${OVERLAY_ROOT}/NOTICE"
/bin/cp "${GHIDRA_SRC_DIR}/DISCLAIMER.md" "${OVERLAY_ROOT}/DISCLAIMER.md"
/bin/cp \
  "${GHIDRA_SRC_DIR}/licenses/zlib_License.txt" \
  "${OVERLAY_ROOT}/licenses/zlib_License.txt"

log_step "Packaging ${TARGET_PLATFORM} overlay"
tar -C "${OVERLAY_ROOT}" -czf "${OVERLAY_TARBALL}" \
  Ghidra LICENSE NOTICE DISCLAIMER.md licenses
write_sha256_file "${OVERLAY_TARBALL}"

echo "Created overlay artifact: ${OVERLAY_TARBALL}"
file "${DECOMPILE_BIN}"
file "${SLEIGH_BIN}"

if [[ "${BUILD_PATCHED_DIST}" == "1" ]]; then
  log_step "Downloading official Ghidra distribution"
  curl -L "${GHIDRA_DIST_URL}" -o "${GHIDRA_DIST_ZIP}" || {
    echo "Error: failed during official Ghidra ZIP download." >&2
    exit 1
  }
  echo "${GHIDRA_DIST_SHA256}  ${GHIDRA_DIST_ZIP}" | if command -v sha256sum >/dev/null 2>&1; then sha256sum -c -; else shasum -a 256 -c -; fi || {
    echo "Error: downloaded official Ghidra ZIP failed SHA256 validation." >&2
    exit 1
  }

  /bin/mkdir -p "${PATCH_ROOT}"
  unzip -q "${GHIDRA_DIST_ZIP}" -d "${PATCH_ROOT}" || {
    echo "Error: failed while unpacking the official Ghidra ZIP." >&2
    exit 1
  }

  RELEASE_DIR=""
  for candidate in "${PATCH_ROOT}"/ghidra_*; do
    if [[ -d "${candidate}" ]]; then
      RELEASE_DIR="${candidate}"
      break
    fi
  done
  [[ -n "${RELEASE_DIR}" ]] || {
    echo "Error: failed to locate unpacked Ghidra release directory." >&2
    exit 1
  }

  /bin/mkdir -p "${RELEASE_DIR}/Ghidra/Features/Decompiler/os/${TARGET_PLATFORM}"
  /bin/cp "${DECOMPILE_BIN}" "${SLEIGH_BIN}" "${RELEASE_DIR}/Ghidra/Features/Decompiler/os/${TARGET_PLATFORM}/"
  /bin/mkdir -p "${RELEASE_DIR}/licenses"
  /bin/cp "${OVERLAY_ROOT}/LICENSE" "${RELEASE_DIR}/LICENSE"
  /bin/cp "${OVERLAY_ROOT}/NOTICE" "${RELEASE_DIR}/NOTICE"
  /bin/cp "${OVERLAY_ROOT}/DISCLAIMER.md" "${RELEASE_DIR}/DISCLAIMER.md"
  /bin/cp \
    "${OVERLAY_ROOT}/licenses/zlib_License.txt" \
    "${RELEASE_DIR}/licenses/zlib_License.txt"

  log_step "Packaging patched ${TARGET_PLATFORM} Ghidra distribution"
  pushd "${PATCH_ROOT}" >/dev/null
  zip -qr "${PATCHED_DIST_ZIP}" "$(/usr/bin/basename "${RELEASE_DIR}")" || {
    echo "Error: failed while creating the patched Ghidra ZIP." >&2
    exit 1
  }
  popd >/dev/null
  write_sha256_file "${PATCHED_DIST_ZIP}"
  echo "Created patched distribution: ${PATCHED_DIST_ZIP}"
fi
