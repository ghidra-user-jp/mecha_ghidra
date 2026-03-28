#!/usr/bin/env sh

set -eu

runtime_arch="$(uname -m)"
case "${runtime_arch}" in
  x86_64)
    decompiler_platform="linux_x86_64"
    ;;
  aarch64|arm64)
    decompiler_platform="linux_arm_64"
    ;;
  *)
    echo >&2 "Error: unsupported Linux architecture '${runtime_arch}'."
    exit 1
    ;;
esac

ghidra_dir="${GHIDRA_INSTALL_DIR:-/opt/ghidra}"
decompiler_path="${ghidra_dir}/Ghidra/Features/Decompiler/os/${decompiler_platform}/decompile"
sleigh_path="${ghidra_dir}/Ghidra/Features/Decompiler/os/${decompiler_platform}/sleigh"

if [ ! -e "${decompiler_path}" ]; then
  echo >&2 "Error: expected Ghidra decompiler was not found at '${decompiler_path}'."
  if [ "${decompiler_platform}" = "linux_arm_64" ]; then
    echo >&2 "Hint: install the mecha_ghidra linux_arm_64 decompiler overlay or use a patched ARM64 Ghidra distribution."
  fi
  exit 1
fi

if [ ! -x "${decompiler_path}" ]; then
  echo >&2 "Error: Ghidra decompiler exists but is not executable: '${decompiler_path}'."
  exit 1
fi

if [ ! -e "${sleigh_path}" ] || [ ! -x "${sleigh_path}" ]; then
  echo >&2 "Error: expected Ghidra sleigh binary was not found or is not executable: '${sleigh_path}'."
  exit 1
fi

exec "$@"
