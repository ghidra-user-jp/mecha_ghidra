[English](development.md) | [日本語](development.ja.md)

# Development Guide

## Development and Testing

- Dependency updates: `uv add <package>` / `uv remove <package>`
- Add formatting/type-check tools as needed and run them with `uv run <tool>`.
- Test run: first install test dependencies (`pytest`, `pytest-mock`) with `uv sync --extra test`, then run unit tests with `uv run pytest`.

## Building Linux ARM64 Decompiler Artifacts

- Run `./scripts/build_linux_arm64_decompiler.sh` to build the `linux_arm_64` decompiler overlay and patched Ghidra distribution.
- On non-Linux ARM64 hosts such as Apple Silicon macOS, the script automatically falls back to a `linux/arm64` Docker container.
- The default outputs are:
  - `dist/ghidra_*_linux_arm_64_decompiler_overlay.tar.gz`
  - `dist/ghidra_*_linux_arm_64_decompiler.zip`
  - matching `.sha256` files
- The GitHub Actions workflow `.github/workflows/release-linux-arm64-decompiler.yml` runs the same build natively on `ubuntu-24.04-arm`.
- For GitHub releases, the workflow now republishes clearer user-facing asset names:
  - `mecha_ghidra_source_code.zip` for the normal repository snapshot
  - `mecha_ghidra_docker_arm64_*.zip` / `*.tar.gz` for Apple Silicon or Linux ARM64 Docker-related artifacts
- The release page body also explains what each asset is for in English.
