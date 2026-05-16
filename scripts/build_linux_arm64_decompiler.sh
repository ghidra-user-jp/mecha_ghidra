#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")" && pwd)"

exec "${SCRIPT_DIR}/build_decompiler_natives.sh" --platform linux_arm_64 "$@"
