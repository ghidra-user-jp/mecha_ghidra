[English](development.md) | [日本語](development.ja.md)

# Development Guide

## Development and Testing

- Dependency updates: `uv add <package>` / `uv remove <package>`
- Install the development tool set with `uv sync --extra dev`; it adds `ruff` and `packaging` on top of the test dependencies.
- Lint and formatting are enforced in CI: run `uv run ruff check src tests` and `uv run ruff format --check src tests` before pushing (`uv run ruff format src tests` rewrites files). The rule set lives in `[tool.ruff]` in `pyproject.toml`; a `# noqa` for a rule that is not enabled fails the lint (RUF100).
- `tests/test_layering.py` enforces the dependency direction between layers (`presentation -> application -> ports -> infrastructure -> ghidra_headless`; `domain`/`contracts` import nothing above them; `ghidra_headless` never imports `ghidra_mcp`). Add a Protocol to `ghidra_mcp/application/services/ports.py` when application code needs a new infrastructure capability.
- `tests/test_spec_handler_parameters.py` checks that every `params.get("...")` key a core handler reads is present in its tool schema; add the field to `tool_spec.py` (and `COMMAND_DEP_KEYS`) when a handler starts reading a new parameter.
- The JVM is started only through `ghidra_headless.launcher.start_headless_jvm()`, which passes `-Djava.awt.headless=true` as a JVM argument, rejects an already-running JVM that is not headless (`JVM_NOT_HEADLESS`), and is shared by the CLI and the real-Ghidra tests. This is required, not cosmetic: mcp 2.x runs tool handlers in worker threads, and on macOS the first AWT initialization from a non-main thread blocks forever waiting for the AppKit main thread. PyGhidra sets the headless property only after the JVM is up, which is too late for `GraphicsEnvironment.isHeadless()`, so the flag must be passed as a JVM argument. Do not call `pyghidra.start()` directly anywhere. Ghidra APIs that need a display fail with `HEADLESS_UNSUPPORTED` instead of hanging.
- Before shipping a change that touches how tools are executed (threads, transports, JVM start-up), run the real-Ghidra validation locally: `GHIDRA_RUNTIME_VALIDATION=1 GHIDRA_INSTALL_DIR=<ghidra> GHIDRA_RUNTIME_BINARY_PATH=/bin/ls uv run pytest tests/test_runtime_readonly_commands.py tests/test_runtime_mutating_commands.py`. The unit suite fakes the JVM and cannot catch thread-affinity problems.
- The MCP SDK is pinned to `mcp>=2.1.1,<3`. Only public SDK APIs (`MCPServer`, `Tool.from_function`, `read_resource`, `run()` keyword arguments) are used; the `latest-mcp-sdk` CI job resolves the newest SDK inside that range and runs the suite as an early warning, and Dependabot opens grouped update PRs for `mcp`/`mcp-types`.
- Programs are opened through `DomainFile.getDomainObject(project, ...)` and released with `Program.release(project)`, never through `GhidraProject.openProgram`. GhidraProject keeps a permanent "Batch Processing" transaction on every program it opens, inside which `isChanged()` stays false, undo never becomes available and a `.gzf` export fails with "Unable to lock due to active transaction". Consequently every mutation must run in its own transaction: tool handlers use `core_helpers._txn`, runtime paths use `ghidra_headless.session.transactions.run_in_transaction` (auto-analysis on first load). Imported programs are still processed under GhidraProject because they are closed immediately after import.
- Module layout for the two largest areas: large-result handling is split into `presentation/result_store.py` (LRU store), `result_compaction.py` (preview/envelope decisions), and `result_tools.py` (`read_result`/`search_result`), with `result_resources.py` as the re-exporting facade. Shared-project sync is `infrastructure/ghidra_adapter/runtime/sync_operations.py` (public operations) plus the `sync_locking`, `sync_identity`, `sync_postconditions`, `sync_active_program`, and `sync_reopen` mixins in the same package.
- The Docker image and `scripts/ghidra_release.env` pin the decompiler natives overlay to a specific release tag (currently `v0.1.4-rc.1`). Bump the URL and SHA256 in both places only when a release changes the natives themselves.
- Test run: first install test dependencies (`pytest`, `pytest-mock`) with `uv sync --extra test`, then run unit tests with `uv run pytest`.
- Runtime validation against a real Ghidra install only runs when `GHIDRA_RUNTIME_VALIDATION=1` is set. Set `GHIDRA_INSTALL_DIR` and `GHIDRA_RUNTIME_BINARY_PATH`; to validate shared-project sync, also set `GHIDRA_RUNTIME_SHARED_PROJECT_LOCATION`, `GHIDRA_RUNTIME_SHARED_PROJECT_NAME`, `GHIDRA_RUNTIME_SHARED_DOMAIN_PATH`, `GHIDRA_RUNTIME_SHARED_SERVER_USER` (or `GHIDRA_SERVER_USER`), and `GHIDRA_SERVER_PASSWORD`.
- BSim runtime validation only runs when `GHIDRA_BSIM_RUNTIME_VALIDATION=1` is set. Set `GHIDRA_INSTALL_DIR` (Ghidra 12.1 is covered), `GHIDRA_BSIM_URL`, and either `GHIDRA_BSIM_PASSWORD` or `GHIDRA_BSIM_PASSWORD_ENV`. To validate query, matched executable loading, and decompilation, also set `GHIDRA_BSIM_PROJECT_LOCATION`, `GHIDRA_BSIM_PROJECT_NAME`, `GHIDRA_BSIM_QUERY_DOMAIN_PATH`, and `GHIDRA_BSIM_QUERY_FUNCTION`. `./scripts/validate_bsim_runtime.sh` sets the runtime-validation flag and can prompt for the BSim password when neither password environment variable is present.
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
- The GitHub Actions workflow `.github/workflows/release-decompiler-natives.yml` builds release decompiler overlays on native hosted runners: `ubuntu-24.04-arm` for `linux_arm_64`, `macos-15` for `mac_arm_64`, and `macos-15-intel` for `mac_x86_64`. The upstream Ghidra 12.1.3 ZIP does not include these three native platform directories.
- Version tag pushes run the Python test/package gate, build the native artifacts, and then publish the generated GitHub release assets. Manual workflow runs build and upload workflow artifacts without publishing a release. Re-running an existing tag updates assets without replacing the existing release notes.
- For GitHub releases, the workflow publishes two user-facing ZIP assets:
  - `ghidra_12.1.3_decompiler_natives_all.zip`: ready-to-use Ghidra 12.1.3 distribution with Linux ARM64 and macOS decompiler files already installed
  - `ghidra_decompiler_natives_all.zip`: overlay ZIP containing the matching Linux ARM64 and macOS decompiler files for an existing Ghidra 12.1.3 install
- The tested `ghidra_mcp` wheel and source distribution built from the release tag are attached to the same GitHub release. Publishing to PyPI remains a separate release-owner step.
- The release overlay adds these native decompiler paths:
- `Ghidra/Features/Decompiler/os/linux_arm_64/decompile`
- `Ghidra/Features/Decompiler/os/linux_arm_64/sleigh`
- `Ghidra/Features/Decompiler/os/mac_arm_64/decompile`
- `Ghidra/Features/Decompiler/os/mac_arm_64/sleigh`
- `Ghidra/Features/Decompiler/os/mac_x86_64/decompile`
- `Ghidra/Features/Decompiler/os/mac_x86_64/sleigh`
- For the normal repository snapshot, use GitHub's built-in `Source code (zip)` / `Source code (tar.gz)` links.
- The release page body explains which ZIP to use and lists those added paths. Separate `.sha256` and older legacy release assets are removed during publish.
