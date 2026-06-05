[English](development.md) | [日本語](development.ja.md)

# Development Guide

## Development and Testing

- Dependency updates: `uv add <package>` / `uv remove <package>`
- Add formatting/type-check tools as needed and run them with `uv run <tool>`.
- Test run: first install test dependencies (`pytest`, `pytest-mock`) with `uv sync --extra test`, then run unit tests with `uv run pytest`.
- Runtime validation against a real Ghidra install only runs when `GHIDRA_RUNTIME_VALIDATION=1` is set. Set `GHIDRA_INSTALL_DIR` and `GHIDRA_RUNTIME_BINARY_PATH`; to validate shared-project sync, also set `GHIDRA_RUNTIME_SHARED_PROJECT_LOCATION`, `GHIDRA_RUNTIME_SHARED_PROJECT_NAME`, `GHIDRA_RUNTIME_SHARED_DOMAIN_PATH`, `GHIDRA_RUNTIME_SHARED_SERVER_USER` (or `GHIDRA_SERVER_USER`), and `GHIDRA_SERVER_PASSWORD`.
- If a running MCP server already has the same Ghidra project open, use a separate local project cache for runtime tests. It may point at the same shared repository, but the local `.gpr` / `.rep` path must be different to avoid project-lock conflicts.

## Building Native Decompiler Artifacts

- Run `./scripts/build_linux_arm64_decompiler.sh` to build the `linux_arm_64` decompiler overlay and patched Ghidra distribution.
- On non-Linux ARM64 hosts such as Apple Silicon macOS, the script automatically falls back to a `linux/arm64` Docker container.
- Run `./scripts/build_decompiler_natives.sh --platform mac_arm_64` on Apple Silicon macOS to build the `mac_arm_64` overlay and patched Ghidra distribution.
- Run `./scripts/build_decompiler_natives.sh --platform mac_x86_64` on Intel macOS to build the `mac_x86_64` overlay and patched Ghidra distribution.
- The default outputs are:
  - `dist/ghidra_*_linux_arm_64_decompiler_overlay.tar.gz`
  - `dist/ghidra_*_linux_arm_64_decompiler.zip`
  - `dist/ghidra_*_mac_arm_64_decompiler_overlay.tar.gz`
  - `dist/ghidra_*_mac_arm_64_decompiler.zip`
  - `dist/ghidra_*_mac_x86_64_decompiler_overlay.tar.gz`
  - `dist/ghidra_*_mac_x86_64_decompiler.zip`
  - matching `.sha256` files for local verification
- The GitHub Actions workflow `.github/workflows/release-decompiler-natives.yml` builds the release Linux ARM64 decompiler overlay on the native hosted runner `ubuntu-24.04-arm`. The upstream Ghidra 12.1.2 ZIP already includes `mac_arm_64` and `mac_x86_64` decompiler binaries.
- Tag pushes and published GitHub releases publish the generated release assets after the release build completes. Manual workflow runs build and upload workflow artifacts without publishing a release.
- For GitHub releases, the workflow publishes two user-facing ZIP assets:
  - `ghidra_12.1.2_decompiler_natives_all.zip`: ready-to-use Ghidra 12.1.2 distribution with the added Linux ARM64 decompiler files already installed
  - `ghidra_decompiler_natives_all.zip`: overlay ZIP containing only the added Linux ARM64 decompiler files for an existing Ghidra 12.1.2 install
- The release overlay adds these native decompiler paths:
  - `Ghidra/Features/Decompiler/os/linux_arm_64/decompile`
  - `Ghidra/Features/Decompiler/os/linux_arm_64/sleigh`
- For the normal repository snapshot, use GitHub's built-in `Source code (zip)` / `Source code (tar.gz)` links.
- The release page body explains which ZIP to use and lists those added paths. Separate `.sha256` and older legacy release assets are removed during publish.
