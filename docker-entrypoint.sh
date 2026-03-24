#!/usr/bin/env sh

set -eu

runtime_arch="$(uname -m)"
if [ "${runtime_arch}" != "x86_64" ]; then
  echo >&2 "Error: Ghidra Linux decompiler requires an x86_64 container, but this container is running as '${runtime_arch}'."
  echo >&2 "Hint: rebuild and run with DOCKER_PLATFORM=linux/amd64 or use ./build_docker_image.sh."
  exit 1
fi

ghidra_dir="${GHIDRA_INSTALL_DIR:-/opt/ghidra}"
decompiler_path="${ghidra_dir}/Ghidra/Features/Decompiler/os/linux_x86_64/decompile"

if [ ! -e "${decompiler_path}" ]; then
  echo >&2 "Error: expected Ghidra decompiler was not found at '${decompiler_path}'."
  exit 1
fi

if [ ! -x "${decompiler_path}" ]; then
  echo >&2 "Error: Ghidra decompiler exists but is not executable: '${decompiler_path}'."
  exit 1
fi

exec "$@"
